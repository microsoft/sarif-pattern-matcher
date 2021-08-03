// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

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

        public static IEnumerable<ValidationResult> ValidateStaticHelper(MethodInfo isValidStaticMethodInfo,
                                                                         IDictionary<string, FlexMatch> groups)
        {
            IEnumerable<ValidationResult> validationResults;

            object[] arguments = new object[]
            {
                groups,
            };

            string currentDirectory = Environment.CurrentDirectory;
            try
            {
                string location = isValidStaticMethodInfo.ReflectedType.Assembly.Location;
                if (!string.IsNullOrWhiteSpace(location))
                {
                    Environment.CurrentDirectory = Path.GetDirectoryName(location);
                }

                validationResults =
                    (IEnumerable<ValidationResult>)isValidStaticMethodInfo.Invoke(
                        obj: null, arguments);
            }
            finally
            {
                Environment.CurrentDirectory = currentDirectory;
            }

            groups = (Dictionary<string, FlexMatch>)arguments[0];

            return validationResults;
        }

        public static ValidationState ValidateDynamicHelper(MethodInfo isValidDynamicMethodInfo,
                                                            ref Fingerprint fingerprint,
                                                            ref string message,
                                                            IDictionary<string, string> options,
                                                            ref ResultLevelKind resultLevelKind)
        {
            ValidationState validationText;

            object[] arguments = new object[]
            {
                fingerprint,
                message,
                options,
                resultLevelKind,
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

            fingerprint = (Fingerprint)arguments[0];
            message = (string)arguments[1];
            options = (Dictionary<string, string>)arguments[2];
            resultLevelKind = (ResultLevelKind)arguments[3];

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

        public IEnumerable<ValidationResult> Validate(string ruleName,
                                                      AnalyzeContext context,
                                                      IDictionary<string, FlexMatch> groups,
                                                      out bool pluginCanPerformDynamicAnalysis)
        {
            return ValidateHelper(RuleNameToValidationMethods,
                                  ruleName,
                                  context,
                                  groups,
                                  out pluginCanPerformDynamicAnalysis);
        }

        public IEnumerable<ValidationResult> Validate(string ruleName,
                                                      AnalyzeContext context,
                                                      IDictionary<string, ISet<FlexMatch>> mergedGroups,
                                                      IList<IDictionary<string, FlexMatch>> combinations,
                                                      IDictionary<string, string> properties,
                                                      out bool pluginCanPerformDynamicAnalysis)
        {
            pluginCanPerformDynamicAnalysis = false;

            var results = new List<ValidationResult>();
            combinations ??= GetCombinations(mergedGroups);

            string filePath = context.TargetUri.GetFilePath();
            var flexMatchProperties = new Dictionary<string, FlexMatch>();
            flexMatchProperties.AddProperties(properties);
            flexMatchProperties["scanTargetFullPath"] = new FlexMatch { Value = filePath };

            foreach (Dictionary<string, FlexMatch> groups in combinations)
            {
                foreach (string key in flexMatchProperties.Keys)
                {
                    groups[key] = flexMatchProperties[key];
                }

                foreach (ValidationResult result in ValidateHelper(RuleNameToValidationMethods,
                                                                   ruleName,
                                                                   context,
                                                                   groups,
                                                                   out pluginCanPerformDynamicAnalysis))
                {
                    result.RegionFlexMatch ??= ConstructRegionFromGroups(groups);
                    results.Add(result);
                }
            }

            return results;
        }

        internal static FlexMatch ConstructRegionFromGroups(IDictionary<string, FlexMatch> groups)
        {
            int minimalOffset = int.MaxValue;
            int maximalOffset = 0;

            if (groups.TryGetValue("secret", out FlexMatch value))
            {
                return value;
            }

            foreach (KeyValuePair<string, FlexMatch> kv in groups)
            {
                // This indicates a reserved value or property
                if (kv.Value.Length == 0 ||
                    int.TryParse(kv.Key, out int result))
                {
                    continue;
                }

                minimalOffset = Math.Min(minimalOffset, kv.Value.Index);
                maximalOffset = Math.Max(maximalOffset, kv.Value.Index + kv.Value.Length);
            }

            return new FlexMatch()
            {
                Index = minimalOffset,
                Length = maximalOffset - minimalOffset,
            };
        }

        internal static IList<IDictionary<string, FlexMatch>> GetCombinations(IDictionary<string, ISet<FlexMatch>> mergedGroups)
        {
            string[] keys = mergedGroups.Keys.ToArray<string>();

            return GetCombinations(mergedGroups, keys, 0, null, null);
        }

        internal static IEnumerable<ValidationResult> ValidateHelper(Dictionary<string, ValidationMethods> ruleIdToMethodMap,
                                                                     string ruleName,
                                                                     AnalyzeContext context,
                                                                     IDictionary<string, FlexMatch> groups,
                                                                     out bool pluginCanPerformDynamicAnalysis)
        {
            pluginCanPerformDynamicAnalysis = false;

            ValidationMethods validationMethods = GetValidationMethods(ruleName, ruleIdToMethodMap);

            if (validationMethods == null)
            {
                var validationResult = new ValidationResult
                {
                    ValidationState = ValidationState.ValidatorNotFound,
                };

                validationResult.Fingerprint = SearchSkimmer.CreateFingerprintFromMatch(groups);

                // This condition occurs in cases when a regex does not provide a group that
                // maps to a fingerprint member. This is the case for binary detections, i.e.,
                // analysis that is simply looking for specific file kinds.
                if (validationResult.Fingerprint == default && context.TargetUri.IsAbsoluteUri)
                {
                    string secret = HashUtilities.ComputeSha256Hash(context.TargetUri.LocalPath);

                    // If we have no static analysis validator, the file itself
                    // is the sensitive asset, and so we will use the hash as the id.
                    validationResult.Fingerprint = new Fingerprint()
                    {
                        Secret = secret,
                    };
                }

                return new[] { validationResult };
            }

            if (validationMethods.DisableDynamicValidationCaching != null)
            {
                DisableValidationCaching(validationMethods.DisableDynamicValidationCaching, context.DisableDynamicValidationCaching);
            }

            IEnumerable<ValidationResult> validationResults = ValidateStaticHelper(validationMethods.IsValidStatic,
                                                                                   groups);

            pluginCanPerformDynamicAnalysis = validationMethods.IsValidDynamic != null;

            if (context.DynamicValidation && pluginCanPerformDynamicAnalysis)
            {
                foreach (ValidationResult validationResult in validationResults)
                {
                    if (validationResult.ValidationState != ValidationState.NoMatch &&
                        validationResult.ValidationState != ValidationState.Expired)
                    {
                        ResultLevelKind resultLevelKind = default;
                        string message = validationResult.Message;
                        IDictionary<string, string> stringGroups = groups.ToStringDictionary();
                        Fingerprint fingerprint = validationResult.Fingerprint;
                        validationResult.ValidationState = ValidateDynamicHelper(validationMethods.IsValidDynamic,
                                                                                 ref fingerprint,
                                                                                 ref message,
                                                                                 stringGroups,
                                                                                 ref resultLevelKind);
                        validationResult.Message = message;
                        validationResult.Fingerprint = fingerprint;
                        validationResult.ResultLevelKind = resultLevelKind;
                    }
                }
            }

            return validationResults;
        }

        private static IList<IDictionary<string, FlexMatch>> GetCombinations(IDictionary<string, ISet<FlexMatch>> mergedGroups,
                                                                            string[] keys,
                                                                            int currentIndex,
                                                                            IList<IDictionary<string, FlexMatch>> combinations,
                                                                            IDictionary<string, FlexMatch> currentCombination)
        {
            combinations ??= new List<IDictionary<string, FlexMatch>>();
            currentCombination ??= new Dictionary<string, FlexMatch>();

            if (currentIndex + 1 > mergedGroups.Count) { return combinations; }

            string key = keys[currentIndex];
            ISet<FlexMatch> currentSet = mergedGroups[key];

            foreach (FlexMatch flexMatch in currentSet)
            {
                Dictionary<string, FlexMatch> copy = currentCombination.Copy();
                copy[key] = flexMatch;

                if (currentIndex + 1 >= mergedGroups.Count)
                {
                    combinations.Add(copy);
                    continue;
                }

                combinations = GetCombinations(mergedGroups, keys, currentIndex + 1, combinations, copy);
            }

            return combinations;
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
                                typeof(Dictionary<string, FlexMatch>), // Regex groups.
                            },
                            null);

                        if (isValidStatic == null || isValidStatic?.ReturnType != typeof(IEnumerable<ValidationResult>))
                        {
                            continue;
                        }

                        MethodInfo isValidDynamic = type.GetMethod(
                            "IsValidDynamic",
                            new[]
                            {
                                typeof(Fingerprint).MakeByRefType(), // Fingerprint.
                                typeof(string).MakeByRefType(), // Message.
                                typeof(Dictionary<string, string>), // Options.
                                typeof(ResultLevelKind).MakeByRefType(), // ResultLevelKind.
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

            assemblyBaseFolder ??= Environment.CurrentDirectory;

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
