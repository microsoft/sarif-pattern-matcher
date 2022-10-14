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
        /// <summary>
        /// This function ensures that if a rule is in the JSON, it has a validator in the assembly.
        /// </summary>
        public static void VerifyAllValidatorsExist(string definitionsFilePath)
        {
            string pluginDirectory = Path.GetDirectoryName(definitionsFilePath);
            string validatorsName = new DirectoryInfo(pluginDirectory).Parent.Name;
            var assembly = Assembly.LoadFrom(Path.Combine(pluginDirectory, $"{validatorsName}.dll"));

            // Read the json file content to get the rule names.
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

            // Not all validators are subclasses of ValidatorBase, so for the time being, we'll have to identify them by name.
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

        /// <summary>
        /// This function ensures that for each shared strings variable definition, 
        /// there is a corresponding regex call to it in the JSON.
        /// </summary>
        public static void VerifyAllJsonRulesExist(string definitionsFilePath)
        {
            string definitionsFileContents = File.ReadAllText(definitionsFilePath);
            SearchDefinitions sdObject = JsonConvert.DeserializeObject<SearchDefinitions>(definitionsFileContents);

            // Load shared strings from file in JSON
            string sharedStringsFileName = sdObject.SharedStringsFileName;
            var definitionsFilePathInfo = new DirectoryInfo(definitionsFilePath);
            string sharedStringsFilePath = Path.Combine(definitionsFilePathInfo.Parent.FullName, sharedStringsFileName);
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

        /// <summary>
        /// This function ensures that for each SEC101_... filename, there is a corresponding rule name and ID match in the JSON.
        /// </summary>
        public static void VerifyAllRuleFilenamesMatchDefinitions(string definitionsFileDirectory)
        {
            // Get all json files from the folder passed with correct security division
            string validatorsFolderName = "SecurePlaintextSecretsValidators";
            string securityDivision = "SEC101";
            var jsonFiles = Directory.GetFiles(definitionsFileDirectory, "*.json").Where(file => file.Contains(securityDivision)).ToList();

            var ruleNameToIdMap = new Dictionary<string, string>();
            var invalidFilenames = new List<string>();

            foreach (string jsonFile in jsonFiles)
            {
                //Read the json file content to get the rule names
                string content = File.ReadAllText(jsonFile);
                SearchDefinitions sdObject = JsonConvert.DeserializeObject<SearchDefinitions>(content);

                foreach (SearchDefinition searchDefinition in sdObject.Definitions)
                {
                    foreach (MatchExpression matchExpression in searchDefinition.MatchExpressions)
                    {
                        string ruleName = matchExpression.Name.Split('/')[1];

                        // Replacing '/' with '_' here enables calling filename.StartsWith() directly on this string.
                        string ruleID = matchExpression.Id.Replace('/', '_');

                        // This will assume all rule IDs are correct (i.e. no duplicates, no erroneous shared IDs).
                        // VerifyAllJsonRulesHaveOnlyOneRuleID will flag if otherwise.
                        if (!ruleNameToIdMap.ContainsKey(ruleName))
                        {
                            ruleNameToIdMap.Add(ruleName, ruleID);
                        }
                    }
                }
            }

            // Load up all Validator files in plugin directory.
            var definitionsDirectory = new DirectoryInfo(definitionsFileDirectory);
            string definitionsParentDirectory = definitionsFileDirectory;
            string validatorsDirectory = Path.Combine(definitionsFileDirectory, validatorsFolderName);
            var validatorsDirectoryInfo = new DirectoryInfo(validatorsDirectory);

            // Load up all Test files in Test.plugin directory.
            definitionsParentDirectory = definitionsDirectory.Parent.FullName;
            string testPluginName = "Tests." + definitionsDirectory.Name;
            string testsDirectory = Path.Combine(definitionsParentDirectory, testPluginName, validatorsFolderName);
            var testsDirectoryInfo = new DirectoryInfo(testsDirectory);

            Assert.True(validatorsDirectoryInfo.Exists && testsDirectoryInfo.Exists,
                "The validator or test directory does not exist." +
                $"{Environment.NewLine}  Validator directory: {validatorsDirectory}" +
                $"{Environment.NewLine}  Test directory: {testsDirectory}");

            // Some useful tools for searching/reading the filenames.
            var rg = new Regex(@"SEC101_[0-9]{3}");
            var sb = new StringBuilder();
            int rulePrefixLength = "SEC101_XXX.".Length;
            string fileEnding = "Validator.cs";

            FileInfo[] ruleFiles = validatorsDirectoryInfo.GetFiles();

            // Run through 2 times, first Validators then Tests files.
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

                    // Check to see if the filename corresponds to a rule, and that the ID is the same.
                    if (!ruleNameToIdMap.ContainsKey(sb.ToString()) || !file.Name.StartsWith(ruleNameToIdMap[sb.ToString()]))
                    {
                        invalidFilenames.Add(file.Name);
                    }
                    sb.Clear();
                }

                // Update what we are looking for on next run.
                ruleFiles = testsDirectoryInfo.GetFiles();
                fileEnding = "ValidatorTests.cs";
            }

            Assert.True(invalidFilenames.Count == 0,
                "These filenames do not match any rule definitions names" +
                $"{Environment.NewLine}  " +
                string.Join($",{Environment.NewLine}  ", invalidFilenames) +
                Environment.NewLine);
        }

        /// <summary>
        /// This function ensures that for each rule in the JSON, it has only one Rule ID issued to it. 
        /// As long as there is a 1:1 correspondence between rule name and rule ID, this will pass.
        /// </summary>
        public static void VerifyAllJsonRulesHaveOnlyOneRuleID(string definitionsFilePath)
        {
            // Read the json file content to get the rule names.
            string content = File.ReadAllText(definitionsFilePath);
            SearchDefinitions sdObject = JsonConvert.DeserializeObject<SearchDefinitions>(content);

            var ruleNameToIdMap = new Dictionary<string, string>();
            var idToRuleNameMap = new Dictionary<string, string>();
            var conflictingRuleIDList = new List<string>();
            var sharedRuleIDList = new List<string>();

            foreach (SearchDefinition searchDefinition in sdObject.Definitions)
            {
                foreach (MatchExpression matchExpression in searchDefinition.MatchExpressions)
                {
                    string ruleName = matchExpression.Name.Split('/')[1];
                    string ruleID = matchExpression.Id;

                    if (!ruleNameToIdMap.ContainsKey(ruleName))
                    {
                        ruleNameToIdMap.Add(ruleName, ruleID);
                    }
                    else
                    {
                        if (!ruleNameToIdMap[ruleName].Equals(ruleID))
                        {
                            conflictingRuleIDList.Add(ruleName);
                        }
                    }

                    if (!idToRuleNameMap.ContainsKey(ruleID))
                    {
                        idToRuleNameMap.Add(ruleID, ruleName);
                    }
                    else
                    {
                        if (!idToRuleNameMap[ruleID].Equals(ruleName))
                        {
                            sharedRuleIDList.Add(ruleID);
                        }
                    }
                }
            }

            var outputmsg = new StringBuilder();
            if (conflictingRuleIDList.Count > 0)
            {
                outputmsg.Append("These rules have multiple conflicting rule IDs issued for them" +
                    $"{Environment.NewLine}  " +
                    string.Join($",{Environment.NewLine}  ", conflictingRuleIDList.Distinct()) +
                    $"{Environment.NewLine}");
            }

            if (sharedRuleIDList.Count > 0)
            {
                outputmsg.Append("These rule IDs have multiple conflicting rules issued for them" +
                    $"{Environment.NewLine}  " +
                    string.Join($",{Environment.NewLine}  ", sharedRuleIDList.Distinct()));
            }


            Assert.True(conflictingRuleIDList.Count == 0 && sharedRuleIDList.Count == 0, outputmsg.ToString());
        }

        /// <summary>
        /// This function ensures that for each regex in the JSON, there is a corresponding definition in the shared strings.
        /// </summary>
        public static void VerifyAllSharedStringsExist(string definitionsFilePath)
        {
            string content = File.ReadAllText(definitionsFilePath);
            SearchDefinitions sdObject = JsonConvert.DeserializeObject<SearchDefinitions>(content);

            // Load shared strings from file in JSON
            string sharedStringsFileName = sdObject.SharedStringsFileName;
            var definitionsFilePathInfo = new DirectoryInfo(definitionsFilePath);
            string sharedStringsFilePath = Path.Combine(definitionsFilePathInfo.Parent.FullName, sharedStringsFileName);

            HashSet<string> regexSet = GetRegexSetFromSearchDefinitions(sdObject);

            var regexesWithoutSharedStrings = new List<string>();
            string sharedStringsContents = File.ReadAllText(sharedStringsFilePath);

            foreach (string regex in regexSet)
            {
                if (regex != null && !sharedStringsContents.Contains(regex))
                {
                    regexesWithoutSharedStrings.Add(regex);
                }
            }

            // Assert.Empty doesn't allow custom messages, so use Assert.True
            Assert.True(regexesWithoutSharedStrings.Count == 0,
                        "Unable to find shared strings for these regular expression variables: " +
                        $"{Environment.NewLine}  " +
                        string.Join($",{Environment.NewLine}  ", regexesWithoutSharedStrings));
        }

        /// <summary>
        /// This function ensures that for each validator in the validator assembly, 
        /// there is a corresponding test in the test assembly, and vice versa.
        /// </summary>
        public static void VerifyAllTestsExist(Assembly validatorsAssembly, Assembly testsAssembly)
        {
            // Not all validators are subclasses of ValidatorBase, so for the time being, we'll have to identify them by name.
            var validators = validatorsAssembly.GetTypes().Where(x => x.Name.EndsWith("Validator")).Select(x => x.Name).ToHashSet();
            var tests = testsAssembly.GetTypes().Where(x => x.Name.EndsWith("ValidatorTests")).Select(x => x.Name).ToHashSet();

            var validatorsWithoutTests = new List<string>();
            var testsWithoutValidators = new List<string>();

            foreach (string validator in validators)
            {
                if (!tests.TryGetValue(validator + "Tests", out string _))
                {
                    // Skip Template Validators.
                    if (validator.Contains("Template")) { continue; }

                    validatorsWithoutTests.Add(validator);
                }
            }

            foreach (string test in tests)
            {
                if (!validators.TryGetValue(test.Replace("Tests", ""), out string _))
                {
                    // Skip Template Validators.
                    if (test.Contains("Template")) { continue; }

                    // Skip SecurePlaintextSecretsPushProtectionTests file.
                    if (test.Contains("SecurePlaintextSecrets")) { continue; }

                    testsWithoutValidators.Add(test);
                }
            }

            var outputmsg = new StringBuilder();
            if (validatorsWithoutTests.Count > 0)
            {
                outputmsg.Append("Unable to find tests for these validators: " +
                        $"{Environment.NewLine}  " +
                        string.Join($",{Environment.NewLine}  ", validatorsWithoutTests) +
                        $"{Environment.NewLine}");
            }
            if (testsWithoutValidators.Count > 0)
            {
                outputmsg.Append("Unable to find validators for these tests: " +
                        $"{Environment.NewLine}  " +
                        string.Join($",{Environment.NewLine}  ", testsWithoutValidators));
            }

            // Assert.Empty doesn't allow custom messages, so use Assert.True
            Assert.True((validatorsWithoutTests.Count == 0 && testsWithoutValidators.Count == 0), outputmsg.ToString());
        }

        /// <summary>
        /// This function returns a HashSet containing all the different types of regex from a SearchDefinitions object.
        /// </summary>
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
    }
}
