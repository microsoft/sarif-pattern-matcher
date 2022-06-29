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
    }
}
