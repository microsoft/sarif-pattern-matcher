﻿// Copyright (c) Microsoft. All rights reserved.
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
        private Dictionary<string, StaticValidatorBase> _ruleNameToValidationMethods;

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

        public Dictionary<string, StaticValidatorBase> RuleNameToValidationMethods
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

        public static StaticValidatorBase GetValidationMethods(string ruleName,
                                                               Dictionary<string, StaticValidatorBase> ruleIdToMethodMap)
        {
            if (ruleName.Contains("/"))
            {
                ruleName = ruleName.Substring(ruleName.IndexOf("/") + 1);
            }

            string validatorName = ruleName + "Validator";

            ruleIdToMethodMap.TryGetValue(validatorName, out StaticValidatorBase validationMethods);
            return validationMethods;
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
            flexMatchProperties["retry"] = new FlexMatch { Value = context.Retry ? bool.TrueString : bool.FalseString };
            flexMatchProperties["enhancedReporting"] = new FlexMatch { Value = context.EnhancedReporting ? bool.TrueString : bool.FalseString };

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

        internal static IEnumerable<ValidationResult> ValidateHelper(Dictionary<string, StaticValidatorBase> ruleIdToMethodMap,
                                                                     string ruleName,
                                                                     AnalyzeContext context,
                                                                     IDictionary<string, FlexMatch> groups,
                                                                     out bool pluginCanPerformDynamicAnalysis)
        {
            pluginCanPerformDynamicAnalysis = false;

            StaticValidatorBase staticValidator = GetValidationMethods(ruleName, ruleIdToMethodMap);

            if (staticValidator == null)
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

            IEnumerable<ValidationResult> validationResults = staticValidator.IsValidStatic(groups);

            if (staticValidator is DynamicValidatorBase dynamicValidator)
            {
                pluginCanPerformDynamicAnalysis = true;

                if (context.DynamicValidation)
                {
                    staticValidator.DisableDynamicValidationCaching(context.DisableDynamicValidationCaching);

                    foreach (ValidationResult validationResult in validationResults)
                    {
                        if (validationResult.ValidationState != ValidationState.NoMatch &&
                            validationResult.ValidationState != ValidationState.Expired)
                        {
                            ResultLevelKind resultLevelKind = default;
                            string message = validationResult.Message;
                            IDictionary<string, string> stringGroups = groups.ToStringDictionary();
                            Fingerprint fingerprint = validationResult.Fingerprint;
                            validationResult.ValidationState = dynamicValidator.IsValidDynamic(ref fingerprint,
                                                                                               ref message,
                                                                                               stringGroups,
                                                                                               ref resultLevelKind);
                            validationResult.Message = message;
                            validationResult.Fingerprint = fingerprint;
                            validationResult.ResultLevelKind = resultLevelKind;
                        }
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

        private Dictionary<string, StaticValidatorBase> LoadValidationAssemblies(IEnumerable<string> validatorPaths)
        {
            var ruleToMethodMap = new Dictionary<string, StaticValidatorBase>();
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

                        if (type.IsClass && !type.IsAbstract && type.IsSubclassOf(typeof(DynamicValidatorBase)))
                        {
                            ruleToMethodMap[typeName] = Activator.CreateInstance(type) as DynamicValidatorBase;
                            continue;
                        }

                        if (type.IsClass && !type.IsAbstract && type.IsSubclassOf(typeof(StaticValidatorBase)))
                        {
                            ruleToMethodMap[typeName] = Activator.CreateInstance(type) as StaticValidatorBase;
                            continue;
                        }
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
            if (this._resolvedNames.TryGetValue(assemblyName, out resolved))
            {
                return resolved;
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

                    this._resolvedNames[assemblyName] = resolved;
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
