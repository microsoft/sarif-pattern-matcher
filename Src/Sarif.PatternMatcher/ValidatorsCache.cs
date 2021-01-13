// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class ValidatorsCache
    {
        private static readonly object sync = new object();
        private static string assemblyBaseFolder;
        private readonly IFileSystem _fileSystem;
        private readonly HashSet<string> _resolvedNames;
        private Dictionary<string, ValidationMethodPair> _ruleIdToValidationMethods;

        public ValidatorsCache(IEnumerable<string> validatorBinaryPaths = null, IFileSystem fileSystem = null)
        {
            ValidatorPaths =
                validatorBinaryPaths != null
                    ? new HashSet<string>(validatorBinaryPaths, StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            _fileSystem = fileSystem ?? FileSystem.Instance;
            _resolvedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        public ISet<string> ValidatorPaths { get; }

        public Validation Validate(
            string ruleId,
            bool dynamicValidation,
            ref string matchedPattern,
            ref IDictionary<string, string> groups,
            ref string failureLevel,
            ref string fingerprint,
            ref string message,
            out bool pluginCanPerformDynamicAnalysis)
        {
            pluginCanPerformDynamicAnalysis = false;

            if (_ruleIdToValidationMethods == null)
            {
                lock (sync)
                {
                    if (_ruleIdToValidationMethods == null)
                    {
                        _ruleIdToValidationMethods ??= LoadValidationAssemblies(ValidatorPaths);
                    }
                }
            }

            return ValidateHelper(
                _ruleIdToValidationMethods,
                ruleId,
                dynamicValidation,
                ref matchedPattern,
                ref groups,
                ref failureLevel,
                ref fingerprint,
                ref message,
                out pluginCanPerformDynamicAnalysis);
        }

        internal static Validation ValidateHelper(
            Dictionary<string, ValidationMethodPair> ruleIdToMethodMap,
            string ruleId,
            bool dynamicValidation,
            ref string matchedPattern,
            ref IDictionary<string, string> groups,
            ref string failureLevel,
            ref string fingerprint,
            ref string message,
            out bool pluginCanPerformDynamicAnalysis)
        {
            pluginCanPerformDynamicAnalysis = false;
            fingerprint = null;
            message = null;

            if (ruleId.Contains("/")) { ruleId = ruleId.Substring(ruleId.IndexOf("/") + 1); }

            string validatorName = ruleId + "Validator";

            if (!ruleIdToMethodMap.TryGetValue(validatorName, out ValidationMethodPair validationPair))
            {
                return Validation.ValidatorNotFound;
            }

            pluginCanPerformDynamicAnalysis = validationPair.IsValidDynamic != null;

            object[] arguments = new object[]
            {
                matchedPattern,
                groups,
                failureLevel,
                fingerprint,
                message,
            };

            string validationText = null;

            string currentDirectory = Environment.CurrentDirectory;
            try
            {
                Environment.CurrentDirectory =
                    Path.GetDirectoryName(validationPair.IsValidStatic.ReflectedType.Assembly.Location);

                validationText =
                    (string)validationPair.IsValidStatic.Invoke(
                        obj: null, arguments);
            }
            finally
            {
                Environment.CurrentDirectory = currentDirectory;
            }

            matchedPattern = (string)arguments[0];
            groups = (Dictionary<string, string>)arguments[1];
            failureLevel = (string)arguments[2];
            fingerprint = (string)arguments[3];
            message = (string)arguments[4];

            if (!Enum.TryParse(validationText, out Validation result))
            {
                return Validation.ValidatorReturnedIllegalValidationState;
            }

            if (!dynamicValidation || validationPair.IsValidDynamic == null)
            {
                if (validationPair.IsValidDynamic != null)
                {
                    // We could have validated but did not as it was not configured. Let the user know there is some functionality they can enable.
                    message += " No validation occurred as it was not enabled. Pass '--dynamic-validation' on the command-line to validate this match";
                }

                return result;
            }

            if (result == Validation.NoMatch)
            {
                return result;
            }

            arguments = new object[]
            {
                fingerprint,
                message,
            };

            currentDirectory = Environment.CurrentDirectory;
            try
            {
                Environment.CurrentDirectory =
                    Path.GetDirectoryName(validationPair.IsValidStatic.ReflectedType.Assembly.Location);

                validationText =
                    (string)validationPair.IsValidDynamic.Invoke(
                        obj: null, arguments);
            }
            finally
            {
                Environment.CurrentDirectory = currentDirectory;
            }

            fingerprint = (string)arguments[0];
            message = (string)arguments[1];

            if (!Enum.TryParse(validationText, out result))
            {
                return Validation.ValidatorReturnedIllegalValidationState;
            }

            return result;
        }

        private Dictionary<string, ValidationMethodPair> LoadValidationAssemblies(IEnumerable<string> validatorPaths)
        {
            var ruleToMethodMap = new Dictionary<string, ValidationMethodPair>();
            AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(CurrentDomain_AssemblyResolve);

            foreach (string validatorPath in validatorPaths)
            {
                Assembly assembly = null;

                if (_fileSystem.FileExists(validatorPath))
                {
                    try
                    {
                        assemblyBaseFolder = Path.GetDirectoryName(validatorPath);
                        assembly = _fileSystem.AssemblyLoadFrom(validatorPath);
                    }
                    catch (ReflectionTypeLoadException)
                    {
                        // TODO log something here.
                    }

                    if (assembly == null) { continue; }

                    foreach (Type type in assembly.GetTypes())
                    {
                        string typeName = type.Name;

                        if (!typeName.EndsWith("Validator") || typeName.Equals("Validator"))
                        {
                            continue;
                        }

                        MethodInfo isValidStatic = type.GetMethod(
                            "IsValidStatic",
                            new[]
                            {
                                typeof(string).MakeByRefType(), // Matched pattern.
                                typeof(Dictionary<string, string>).MakeByRefType(), // Regex groups.
                                typeof(string).MakeByRefType(), // FailureLevel.
                                typeof(string).MakeByRefType(), // Fingerprint.
                                typeof(string).MakeByRefType(), // Message.
                            },
                            null);

                        if (isValidStatic == null || isValidStatic?.ReturnType != typeof(string))
                        {
                            continue;
                        }

                        MethodInfo isValidDynamic = type.GetMethod(
                            "IsValidDynamic",
                            new[]
                            {
                                typeof(string).MakeByRefType(), // Fingerprint.
                                typeof(string).MakeByRefType(), // Message.
                            },
                            null);

                        if (isValidDynamic?.ReturnType != typeof(string))
                        {
                            isValidDynamic = null;
                        }

                        ruleToMethodMap[typeName] = new ValidationMethodPair
                        {
                            IsValidStatic = isValidStatic,
                            IsValidDynamic = isValidDynamic,
                        };
                    }
                }
            }

            return ruleToMethodMap;
        }

        private Assembly CurrentDomain_AssemblyResolve(object sender, ResolveEventArgs args)
        {
            Assembly resolved = null;

            // We will only attempt to resolve an assembly a single time
            // to avoid re-entrance in cases where our logic below fails
            string assemblyName = args.Name.Split(',')[0];
            if (this._resolvedNames.Contains(assemblyName))
            {
                return null;
            }

            this._resolvedNames.Add(assemblyName);

            if (assemblyBaseFolder.EndsWith("analyze\\..\\bin"))
            {
                assemblyBaseFolder = assemblyBaseFolder.Replace("analyze\\..\\bin", string.Empty);
            }

            string presumedAssemblyPath = Path.Combine(assemblyBaseFolder, Path.GetFileName(assemblyName));

            if (!presumedAssemblyPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
                !presumedAssemblyPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                presumedAssemblyPath += ".dll";

                if (!File.Exists(presumedAssemblyPath))
                {
                    // Strip .dll and give .exe a whirl
                    presumedAssemblyPath = Path.Combine(assemblyBaseFolder, assemblyName) + ".exe";
                }
            }

            if (File.Exists(presumedAssemblyPath))
            {
                try
                {
                    // If we use Assembly.LoadFrom, a FileLoadException
                    // saying that it could not load the file.
                    resolved = Assembly.Load(_fileSystem.FileReadAllBytes(presumedAssemblyPath));
                }
                catch (IOException) { }
                catch (TypeLoadException) { }
                catch (BadImageFormatException) { }
                catch (UnauthorizedAccessException) { }
            }

            return resolved;
        }
    }
}
