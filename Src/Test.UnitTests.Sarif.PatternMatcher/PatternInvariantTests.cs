// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

using Newtonsoft.Json;
using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    /// <summary>
    /// These tests enforce certain invariants around the scan rules, e.g., that we can
    /// associate every rule in a definitions JSON with its corresponding rule definitions
    /// in its shared strings file, that the rule ships a code-based validator, etc.
    /// </summary>
    public class PatternInvariantTests
    {
        public static void VerifyAllValidatorsExist(string definitionsFilePath)
        {
            string pluginDirectory = Path.GetDirectoryName(definitionsFilePath);
            string validatorsName = new DirectoryInfo(pluginDirectory).Parent.Name;
            var assembly = Assembly.LoadFrom(Path.Combine(pluginDirectory, $"{validatorsName}.dll"));

            //Read the json file content to get the rule names
            string content = File.ReadAllText(definitionsFilePath);
            SearchDefinitions sdObject = JsonConvert.DeserializeObject<SearchDefinitions>(content);
            var rules = new HashSet<string>();
            foreach (SearchDefinition searchDefinition in sdObject.Definitions)
            {
                foreach (MatchExpression matchExpression in searchDefinition.MatchExpressions)
                {
                    rules.Add(matchExpression.Name.Split('/')[1]);
                }
            }

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
            Assert.True(rulesWithoutValidators.Count == 0,
                        "Unable to find validators for these rules: " +
                        $"{Environment.NewLine}  " +
                        string.Join($",{Environment.NewLine}  ", rulesWithoutValidators));
        }

        public static void VerifyAllRuleFilenamesMatchDefinitions(string definitionsFilePath)
        {
            //Read the json file content to get the rule names
            string content = File.ReadAllText(definitionsFilePath);
            SearchDefinitions sdObject = JsonConvert.DeserializeObject<SearchDefinitions>(content);
            var regexSet = new HashSet<string>();
            foreach (SearchDefinition searchDefinition in sdObject.Definitions)
            {
                foreach (MatchExpression matchExpression in searchDefinition.MatchExpressions)
                {
                    regexSet.Add(matchExpression.Name.Split('/')[1]);
                }
            }

            // Load up all Validator files in plugin directory
            var definitionsDirectory = new DirectoryInfo(definitionsFilePath);
            string definitionsParentDirectory = definitionsDirectory.Parent.FullName;
            string validatorsDirectory = Path.Combine(definitionsParentDirectory, "SecurePlaintextSecretsValidators");
            var validatorsDirectoryInfo = new DirectoryInfo(validatorsDirectory);

            // load up all Test files in Test.plugin directory
            definitionsParentDirectory = definitionsDirectory.Parent.Parent.FullName;
            string testPluginName = "Tests." + definitionsDirectory.Parent.Name;
            string testsDirectory = Path.Combine(definitionsParentDirectory, testPluginName, "SecurePlaintextSecretsValidators");
            var testsDirectoryInfo = new DirectoryInfo(testsDirectory);

            // Some useful tools for searching/reading the filenames
            var rg = new Regex(@"SEC101_[0-9]{3}");
            var sb = new StringBuilder();
            var invalidFilenames = new List<string>();
            int rulePrefixLength = "SEC101_XXX.".Length;
            string fileEnding = "Validator.cs";

            FileInfo[] ruleFiles = validatorsDirectoryInfo.GetFiles();

            // Run through 2 times, first Validators then Tests files
            for (int i = 0; i < 2; i++)
            {
                foreach (FileInfo file in ruleFiles)
                {
                    if (!file.Name.StartsWith("SEC101_") || !rg.IsMatch(file.Name))
                    {
                        continue;
                    }

                    sb.Append(file.Name);
                    sb.Remove(0, rulePrefixLength);
                    sb.Replace(fileEnding, "");

                    if (!regexSet.Contains(sb.ToString()))
                    {
                        invalidFilenames.Add(file.Name);
                    }
                    sb.Clear();
                }

                // Update what we are looking for on next run
                ruleFiles = testsDirectoryInfo.GetFiles();
                fileEnding = "ValidatorTests.cs";
            }

            Assert.True(invalidFilenames.Count == 0,
                "These filenames do not match any rule definitions names" +
                $"{Environment.NewLine}  " +
                string.Join($",{Environment.NewLine}  ", invalidFilenames));

        }

        public static void VerifyAllSharedStringsExist(string definitionsFilePath, string sharedStringsFilePath)
        {
            string content = File.ReadAllText(definitionsFilePath);

            SearchDefinitions sdObject = JsonConvert.DeserializeObject<SearchDefinitions>(content);

            HashSet<string> regexSet = GetRegexSetFromSearchDefinitions(sdObject);

            var rulesWithoutSharedStrings = new List<string>();
            string sharedStringsContents = File.ReadAllText(sharedStringsFilePath);
            foreach (string rule in regexSet)
            {
                if (!sharedStringsContents.Contains(rule))
                {
                    rulesWithoutSharedStrings.Add(rule);
                }
            }

            // Assert.Empty doesn't allow custom messages, so use Assert.True
            Assert.True(rulesWithoutSharedStrings.Count == 0,
                        "Unable to find shared strings for these regular expression variables: " +
                        $"{Environment.NewLine}  " +
                        string.Join($",{Environment.NewLine}  ", rulesWithoutSharedStrings));
        }

        public static HashSet<string> GetRegexSetFromSearchDefinitions(SearchDefinitions sdObject)
        {
            var regexSet = new HashSet<string>();
            foreach (SearchDefinition searchDefinition in sdObject.Definitions)
            {
                // Add all types of regexes in Definitons or MatchExpressions to hashset
                if (!string.IsNullOrWhiteSpace(searchDefinition.FileNameAllowRegex))
                {
                    regexSet.Add(searchDefinition.FileNameAllowRegex);
                }
                if (!string.IsNullOrWhiteSpace(searchDefinition.FileNameDenyRegex))
                {
                    regexSet.Add(searchDefinition.FileNameDenyRegex);
                }

                foreach (MatchExpression matchExpression in searchDefinition.MatchExpressions)
                {
                    if (!string.IsNullOrWhiteSpace(matchExpression.FileNameAllowRegex))
                    {
                        regexSet.Add(matchExpression.FileNameAllowRegex);
                    }
                    if (!string.IsNullOrWhiteSpace(matchExpression.FileNameDenyRegex))
                    {
                        regexSet.Add(matchExpression.FileNameDenyRegex);
                    }
                    if (!string.IsNullOrWhiteSpace(matchExpression.ContentsRegex))
                    {
                        regexSet.Add(matchExpression.ContentsRegex);
                    }
                    if (matchExpression.IntrafileRegexes != null)
                    {
                        foreach (string intrafileregex in matchExpression.IntrafileRegexes)
                        {
                            if (!string.IsNullOrWhiteSpace(intrafileregex))
                            {
                                regexSet.Add(intrafileregex);
                            }
                        }

                    }
                    if (matchExpression.SingleLineRegexes != null)
                    {
                        foreach (string singleLineRegex in matchExpression.SingleLineRegexes)
                        {
                            if (!string.IsNullOrWhiteSpace(singleLineRegex))
                            {
                                regexSet.Add(singleLineRegex);
                            }
                        }
                    }
                }
            }
            return regexSet;
        }

        public static void VerifyAllJsonRulesExist(string definitionsFilePath, string sharedStringsFilePath)
        {
            // This function verifies that for each shared string variable definition, there is a rule in the JSON that uses it
            string definitionsFileContents = File.ReadAllText(definitionsFilePath);
            string sharedStringsContents = File.ReadAllText(sharedStringsFilePath);

            string line;
            var reader = new StringReader(sharedStringsContents);

            var sharedStringsWithoutRules = new List<string>();
            while ((line = reader.ReadLine()) != null)
            {
                line = line.Trim();
                if (!line.StartsWith('$'))
                {
                    continue;
                }

                line = line.Split('=')[0];
                if (!definitionsFileContents.Contains(line))
                {
                    sharedStringsWithoutRules.Add(line);
                }
            }
            // Assert.Empty doesn't allow custom messages, so use Assert.True
            Assert.True(sharedStringsWithoutRules.Count == 0,
                        "Found no reference to these regular expression definitions in JSON: " +
                        $"{Environment.NewLine}  " +
                        string.Join($",{Environment.NewLine}  ", sharedStringsWithoutRules));

        }
        public static void VerifyAllTestsExist(Assembly validatorsAssembly, Assembly testsAssembly)
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
            Assert.True(rulesWithoutTests.Count == 0,
                        "Unable to find tests for these rules: " +
                        $"{Environment.NewLine}  " +
                        string.Join($",{Environment.NewLine}  ", rulesWithoutTests));
        }
    }
}

