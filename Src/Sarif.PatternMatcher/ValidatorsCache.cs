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
        private readonly IFileSystem _fileSystem;
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
            ref string matchedPattern,
            ref IDictionary<string, string> groups,
            ref bool dynamicValidation,
            ref string failureLevel,
            ref string fingerprint,
            out string validatorMessage)
        {
            if (_ruleIdToMethodMap == null)
            {
                lock (sync)
                {
                    if (_ruleIdToMethodMap == null)
                    {
                        _ruleIdToMethodMap ??= LoadValidationAssemblies(ValidatorPaths);
                    }
                }
            }

            return ValidateHelper(
                _ruleIdToMethodMap,
                ruleId,
                ref matchedPattern,
                ref groups,
                ref dynamicValidation,
                ref failureLevel,
                ref fingerprint,
                out validatorMessage);
        }

        internal static Validation ValidateHelper(
            Dictionary<string, MethodInfo> ruleIdToMethodMap,
            string ruleId,
            ref string matchedPattern,
            ref IDictionary<string, string> groups,
            ref bool dynamicValidation,
            ref string failureLevel,
            ref string fingerprint,
            out string validatorMessage)
        {
            fingerprint = null;
            validatorMessage = null;

            if (ruleId.Contains("/")) { ruleId = ruleId.Substring(ruleId.IndexOf("/") + 1); }

            string validatorName = ruleId + "Validator";

            if (!ruleIdToMethodMap.TryGetValue(validatorName, out MethodInfo methodInfo))
            {
                return Validation.ValidatorNotFound;
            }

            object[] arguments = new object[]
            {
                matchedPattern,
                groups,
                dynamicValidation,
                failureLevel,
                fingerprint,
            };

            string validationText = null;

            string currentDirectory = Environment.CurrentDirectory;
            try
            {
                Environment.CurrentDirectory =
                    Path.GetDirectoryName(methodInfo.ReflectedType.Assembly.Location);

                validationText =
                    (string)methodInfo.Invoke(
                        obj: null, arguments);
            }
            finally
            {
                Environment.CurrentDirectory = currentDirectory;
            }

            matchedPattern = (string)arguments[0];
            groups = (Dictionary<string, string>)arguments[1];
            dynamicValidation = (bool)arguments[2];
            failureLevel = (string)arguments[3];
            fingerprint = (string)arguments[4];

            string[] tokens = validationText.Split('#');

            if (!Enum.TryParse<Validation>(tokens[0], out Validation result))
            {
                // TODO: raise an exception and disable this validator, which
                // is returning illegal values.
                return Validation.ValidatorReturnedIllegalValue;
            }

            if (tokens.Length > 1)
            {
                validatorMessage = $" {tokens[1]}".Trim();
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
                            new[]
                            {
                                typeof(string).MakeByRefType(),
                                typeof(Dictionary<string, string>).MakeByRefType(),
                                typeof(bool).MakeByRefType(),
                                typeof(string).MakeByRefType(),
                                typeof(string).MakeByRefType(),
                            },
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
