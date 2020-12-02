// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher
{
    public class ValidatorsCache
    {
        private readonly IEnumerable<string> _searchDefinitionsPaths;
        private Dictionary<string, MethodInfo> _ruleIdToMethodMap;

        public ValidatorsCache(IEnumerable<string> searchDefinitionsPaths)
        {
            _searchDefinitionsPaths = searchDefinitionsPaths;
        }

        public Validation Validate(string ruleId, string matchedPattern)
        {
            _ruleIdToMethodMap ??= LoadValidationAssemblies(_searchDefinitionsPaths);

            return ValidateHelper(_ruleIdToMethodMap, ruleId, matchedPattern);
        }

        internal static Validation ValidateHelper(
            Dictionary<string, MethodInfo> ruleIdToMethodMap,
            string ruleId,
            string matchedPattern)
        {
            string validatorName = ruleId + "Validator";

            if (!ruleIdToMethodMap.TryGetValue(validatorName, out MethodInfo methodInfo))
            {
                return Validation.ValidatorNotFound;
            }

            return (bool)methodInfo.Invoke(obj: null, new object[] { matchedPattern }) ?
                Validation.Valid :
                Validation.Invalid;
        }

        private static Dictionary<string, MethodInfo> LoadValidationAssemblies(IEnumerable<string> searchDefinitionsPaths)
        {
            var ruleToMethodMap = new Dictionary<string, MethodInfo>();

            foreach (string searchDefinitionPath in searchDefinitionsPaths)
            {
                Assembly assembly = null;
                string assemblyPath = Path.GetDirectoryName(searchDefinitionPath);
                assemblyPath = Path.Combine(assemblyPath, Path.GetFileNameWithoutExtension(searchDefinitionPath) + ".dll");

                if (File.Exists(assemblyPath))
                {
                    try
                    {
                        assembly = Assembly.LoadFrom(assemblyPath);
                    }
                    catch (ReflectionTypeLoadException)
                    {
                        // TODO log                    
                    }

                    if (assembly == null) { continue; }

                    foreach (Type type in assembly.GetTypes())
                    {
                        string typeName = type.Name;

                        if (!typeName.EndsWith("Validator") || typeName.Equals("Validator"))
                        {
                            continue;
                        }

                        MethodInfo mi = type.GetMethod("IsValid", BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
                        if (mi == null || mi.ReturnType != typeof(bool)) { continue; }

                        ruleToMethodMap[typeName] = mi;
                    }
                }
            }

            return ruleToMethodMap;
        }
    }
}
