// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

using Newtonsoft.Json.Linq;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class ReflectionTests
    {
        public static void VerifyAllValidatorsExist(string definitionsFileName, Assembly assembly)
        {
            try
            {
                if (!File.Exists(definitionsFileName))
                {
                    return;
                }

                string content = File.ReadAllText(definitionsFileName);

                var jObject = (JObject)JToken.Parse(content);

                IEnumerable<string> rules = jObject["Definitions"][0]["MatchExpressions"].Select(x => x["Name"].ToString().Split('/')[1]).Distinct();

                // Not all validators are subclasses of ValidatorBase, so for the time being, we'll have to identify them by name
                var validators = assembly.GetTypes().Where(x => x.Name.EndsWith("Validator")).Select(x => x.Name).ToHashSet();

                var rulesWithoutValidators = new List<string>();

                foreach (string rule in rules)
                {
                    if (!validators.TryGetValue(rule + "Validator", out string _))
                    {
                        rulesWithoutValidators.Add(rule);
                    }
                }

                // Assert.Empty doesn't allow custom messages, so use Assert.True
                Assert.True(rulesWithoutValidators.Count == 0, "Unable to find validators for these rules: " + string.Join(',', rulesWithoutValidators));
            }
            catch (IOException ioe)
            {
                Assert.True(false, "Failed to read the rules file.  Exception was: " + ioe.Message);
            }
            catch (NullReferenceException)
            {
                Assert.True(false, "Unexpected JSON structure in rules file");
            }
        }

        public static void VerifyAllSharedStringsExist(string definitionsFilePath, string sharedStringsFilePath)
        {
            try
            {
                if (!File.Exists(definitionsFilePath) || !File.Exists(sharedStringsFilePath))
                {
                    return;
                    // Should we Assert.True(false) here?
                }

                string content = File.ReadAllText(definitionsFilePath);

                var jObject = (JObject)JToken.Parse(content);

                IEnumerable<string> rules = jObject["Definitions"][0]["MatchExpressions"].Select(x => x["ContentsRegex"].ToString()).Distinct();

                var rulesWithoutSharedStrings = new List<string>();
                string sharedStringsContents;
                using (var sr = new StreamReader(sharedStringsFilePath))
                {
                    sharedStringsContents = sr.ReadToEnd();
                }

                foreach (string rule in rules)
                {
                    if (!sharedStringsContents.Contains(rule))
                    {
                        rulesWithoutSharedStrings.Add(rule);
                    }
                }

                // Assert.Empty doesn't allow custom messages, so use Assert.True
                Assert.True(rulesWithoutSharedStrings.Count == 0, "Unable to find shared strings for these rules: " + string.Join(',', rulesWithoutSharedStrings));
            }
            catch (IOException ioe)
            {
                Assert.True(false, "Failed to read the rules file.  Exception was: " + ioe.Message);
            }
            catch (NullReferenceException)
            {
                Assert.True(false, "Unexpected JSON structure in rules file");
            }
        }

        public static void VerifyAllTestsExist(Assembly validatorsAssembly, Assembly testsAssembly)
        {
            try
            {
                // Not all validators are subclasses of ValidatorBase, so for the time being, we'll have to identify them by name
                var validators = validatorsAssembly.GetTypes().Where(x => x.Name.EndsWith("Validator")).Select(x => x.Name).ToHashSet();
                var tests = testsAssembly.GetTypes().Where(x => x.Name.EndsWith("ValidatorTests")).Select(x => x.Name).ToHashSet();

                var rulesWithoutTests = new List<string>();

                foreach (string validator in validators)
                {
                    if (!tests.TryGetValue(validator + "Tests", out string _))
                    {
                        // Skip Template Validators
                        if (validator.Contains("Template")) { continue; }

                        rulesWithoutTests.Add(validator);
                    }
                }
                // Assert.Empty doesn't allow custom messages, so use Assert.True
                Assert.True(rulesWithoutTests.Count == 0, "Unable to find tests for these rule validators: " + string.Join(',', rulesWithoutTests));
            }
            catch (IOException ioe)
            {
                Assert.True(false, "Failed to read the rules file.  Exception was: " + ioe.Message);
            }
            catch (NullReferenceException)
            {
                Assert.True(false, "Unexpected JSON structure in rules file");
            }

        }
    }
}
