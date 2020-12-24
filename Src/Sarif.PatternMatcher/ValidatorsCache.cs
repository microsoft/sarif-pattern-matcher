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
        private IFileSystem _fileSystem;
        private Dictionary<string, MethodInfo> _ruleIdToMethodMap;

        public ValidatorsCache(IEnumerable<string> validatorBinaryPaths = null, IFileSystem fileSystem = null)
        {
            ValidatorPaths =
                validatorBinaryPaths != null
                    ? new HashSet<string>(validatorBinaryPaths, StringComparer.OrdinalIgnoreCase)
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            _fileSystem = fileSystem ?? FileSystem.Instance;
        }

        public ISet<string> ValidatorPaths { get; }

        public Validation Validate(
            string ruleId,
            string matchedPattern,
            ref bool dynamicValidation,
            ref string failureLevel,
            out string validatorMessage)
        {
            _ruleIdToMethodMap ??= LoadValidationAssemblies(ValidatorPaths);

            return ValidateHelper(_ruleIdToMethodMap,
                ruleId,
                matchedPattern,
                ref dynamicValidation,
                ref failureLevel,
                out validatorMessage);
        }

        internal static Validation ValidateHelper(
            Dictionary<string, MethodInfo> ruleIdToMethodMap,
            string ruleId,
            string matchedPattern,
            ref bool dynamicValidation,
            ref string failureLevel,
            out string validatorMessage)
        {
            validatorMessage = null;
            string validatorName = ruleId + "Validator";

            if (!ruleIdToMethodMap.TryGetValue(validatorName, out MethodInfo methodInfo))
            {
                return Validation.ValidatorNotFound;
            }

            object[] arguments = new object[] { matchedPattern, dynamicValidation, failureLevel };

            string validationText =
                (string)methodInfo.Invoke(
                    obj: null, arguments);

            dynamicValidation = (bool)arguments[1];
            failureLevel = (string)arguments[2];

            string[] tokens = validationText.Split('#');

            if (!Enum.TryParse<Validation>(tokens[0], out Validation result))
            {
                // TODO: raise an exception and disable this validator, which
                // is returning illegal values.
                return Validation.ValidatorNotFound;
            }

            if (tokens.Length > 1)
            {
                validatorMessage = tokens[1];
            }

            return result;
        }

        private Dictionary<string, MethodInfo> LoadValidationAssemblies(IEnumerable<string> validatorPaths)
        {
            var ruleToMethodMap = new Dictionary<string, MethodInfo>();

            foreach (string validatorPath in validatorPaths)
            {
                Assembly assembly = null;

                if (_fileSystem.FileExists(validatorPath))
                {
                    try
                    {
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

                        MethodInfo mi = type.GetMethod(
                            "IsValid",
                            new[] { typeof(string), typeof(bool).MakeByRefType(), typeof(string).MakeByRefType() },
                            null);

                        if (mi == null || mi.ReturnType != typeof(string)) { continue; }

                        ruleToMethodMap[typeName] = mi;
                    }
                }
            }

            return ruleToMethodMap;
        }
    }
}
