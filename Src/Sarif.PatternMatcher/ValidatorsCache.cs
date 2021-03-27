// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class ValidatorsCache
    {
        private static readonly object sync = new object();
        private static string assemblyBaseFolder;
        private readonly IFileSystem _fileSystem;
        private readonly Dictionary<string, Assembly> _resolvedNames;
        private Dictionary<string, ValidationMethods> _ruleNameToValidationMethods;

        public ValidatorsCache(IEnumerable<string> validatorBinaryPaths = null, IFileSystem fileSystem = null)
        {
            ValidatorPaths =
                validatorBinaryPaths != null
                    ? new HashSet<string>(validatorBinaryPaths, StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            _fileSystem = fileSystem ?? FileSystem.Instance;
            _resolvedNames = new Dictionary<string, Assembly>(StringComparer.OrdinalIgnoreCase);
        }

        public ISet<string> ValidatorPaths { get; }

        public Dictionary<string, ValidationMethods> RuleNameToValidationMethods
        {
            get
            {
                if (_ruleNameToValidationMethods == null)
                {
                    lock (sync)
                    {
                        if (_ruleNameToValidationMethods == null)
                        {
                            _ruleNameToValidationMethods ??= LoadValidationAssemblies(ValidatorPaths);
                        }
                    }
                }

                return _ruleNameToValidationMethods;
            }
        }

        public static ValidationMethods GetValidationMethods(string ruleName,
                                                                   Dictionary<string, ValidationMethods> ruleIdToMethodMap)
        {
            if (ruleName.Contains("/"))
            {
                ruleName = ruleName.Substring(ruleName.IndexOf("/") + 1);
            }

            string validatorName = ruleName + "Validator";

            ruleIdToMethodMap.TryGetValue(validatorName, out ValidationMethods validationMethods);
            return validationMethods;
        }

        public static ValidationState ValidateStaticHelper(MethodInfo isValidStaticMethodInfo,
                                                       ref string matchedPattern,
                                                       ref IDictionary<string, string> groups,
                                                       ref string failureLevel,
                                                       ref string fingerprint,
                                                       ref string message)
        {
            ValidationState validationState;

            object[] arguments = new object[]
            {
                matchedPattern,
                groups,
                failureLevel,
                fingerprint,
                message,
            };

            string currentDirectory = Environment.CurrentDirectory;
            try
            {
                string location = isValidStaticMethodInfo.ReflectedType.Assembly.Location;
                if (!string.IsNullOrWhiteSpace(location))
                {
                    Environment.CurrentDirectory = Path.GetDirectoryName(location);
                }

                validationState =
                    (ValidationState)isValidStaticMethodInfo.Invoke(
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

            return validationState;
        }

        public static ValidationState ValidateDynamicHelper(MethodInfo isValidDynamicMethodInfo,
                                                       ref string fingerprint,
                                                       ref string message,
                                                       ref IDictionary<string, string> options)
        {
            ValidationState validationText;

            object[] arguments = new object[]
            {
                fingerprint,
                message,
                options,
            };

            string currentDirectory = Environment.CurrentDirectory;
            try
            {
                string location = isValidDynamicMethodInfo.ReflectedType.Assembly.Location;
                if (!string.IsNullOrWhiteSpace(location))
                {
                    Environment.CurrentDirectory = Path.GetDirectoryName(location);
                }

                validationText =
                    (ValidationState)isValidDynamicMethodInfo.Invoke(
                        obj: null, arguments);
            }
            finally
            {
                Environment.CurrentDirectory = currentDirectory;
            }

            fingerprint = (string)arguments[0];
            message = (string)arguments[1];
            options = (Dictionary<string, string>)arguments[2];

            return validationText;
        }

        public static void DisableValidationCaching(MethodInfo shouldCacheMethodInfo, bool disableValidationCaching)
        {
            object[] arguments = new object[]
            {
                disableValidationCaching,
            };

            string currentDirectory = Environment.CurrentDirectory;
            try
            {
                string location = shouldCacheMethodInfo.ReflectedType.Assembly.Location;
                if (!string.IsNullOrWhiteSpace(location))
                {
                    Environment.CurrentDirectory = Path.GetDirectoryName(location);
                }

                shouldCacheMethodInfo.Invoke(obj: null, arguments);
            }
            finally
            {
                Environment.CurrentDirectory = currentDirectory;
            }
        }

        public ValidationState Validate(
            string ruleName,
            AnalyzeContext context,
            ref string matchedPattern,
            ref IDictionary<string, string> groups,
            ref string failureLevel,
            ref string fingerprint,
            ref string message,
            out bool pluginCanPerformDynamicAnalysis)
        {
            pluginCanPerformDynamicAnalysis = false;

            return ValidateHelper(
                RuleNameToValidationMethods,
                ruleName,
                context,
                ref matchedPattern,
                ref groups,
                ref failureLevel,
                ref fingerprint,
                ref message,
                out pluginCanPerformDynamicAnalysis);
        }

        internal static ValidationState ValidateHelper(
            Dictionary<string, ValidationMethods> ruleIdToMethodMap,
            string ruleName,
            AnalyzeContext context,
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

            ValidationMethods validationMethods = GetValidationMethods(ruleName, ruleIdToMethodMap);

            if (validationMethods == null)
            {
                return ValidationState.ValidatorNotFound;
            }

            if (validationMethods.DisableDynamicValidationCaching != null)
            {
                DisableValidationCaching(validationMethods.DisableDynamicValidationCaching, context.DisableDynamicValidationCaching);
            }

            ValidationState result = ValidateStaticHelper(validationMethods.IsValidStatic,
                                                     ref matchedPattern,
                                                     ref groups,
                                                     ref failureLevel,
                                                     ref fingerprint,
                                                     ref message);

            pluginCanPerformDynamicAnalysis = validationMethods.IsValidDynamic != null;

            return (result != ValidationState.NoMatch && result != ValidationState.Expired && context.DynamicValidation && pluginCanPerformDynamicAnalysis) ?
                ValidateDynamicHelper(validationMethods.IsValidDynamic, ref fingerprint, ref message, ref groups) :
                result;
        }

        private Dictionary<string, ValidationMethods> LoadValidationAssemblies(IEnumerable<string> validatorPaths)
        {
            var ruleToMethodMap = new Dictionary<string, ValidationMethods>();
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

                        if (isValidStatic == null || isValidStatic?.ReturnType != typeof(ValidationState))
                        {
                            continue;
                        }

                        MethodInfo isValidDynamic = type.GetMethod(
                            "IsValidDynamic",
                            new[]
                            {
                                typeof(string).MakeByRefType(), // Fingerprint.
                                typeof(string).MakeByRefType(), // Message.
                                typeof(Dictionary<string, string>).MakeByRefType(), // Options.
                            },
                            null);

                        if (isValidDynamic?.ReturnType != typeof(ValidationState))
                        {
                            isValidDynamic = null;
                        }

                        MethodInfo disableDynamicValidationCaching = type.BaseType.GetMethod(
                            "DisableDynamicValidationCaching",
                            new[]
                            {
                                typeof(bool),
                            },
                            null);

                        ruleToMethodMap[typeName] = new ValidationMethods
                        {
                            IsValidStatic = isValidStatic,
                            IsValidDynamic = isValidDynamic,
                            DisableDynamicValidationCaching = disableDynamicValidationCaching,
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
            if (this._resolvedNames.ContainsKey(assemblyName))
            {
                return this._resolvedNames[assemblyName];
            }

            AppDomain currentDomain = AppDomain.CurrentDomain;
            Assembly[] assemblies = currentDomain.GetAssemblies();
            foreach (Assembly assembly in assemblies)
            {
                if (assembly.FullName.Split(',')[0] == assemblyName)
                {
                    return assembly;
                }
            }

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

                    this._resolvedNames.Add(assemblyName, resolved);
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
