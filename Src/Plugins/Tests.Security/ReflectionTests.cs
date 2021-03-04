// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class ReflectionTests
    {
        public void All101Rules_ShouldHaveValidators()
        {
            try
            {
                using (StreamReader file = File.OpenText(@"SEC101.SecurePlaintextSecrets.json"))
                using (JsonTextReader reader = new JsonTextReader(file))
                {
                    JObject o2 = (JObject)JToken.ReadFrom(reader);

                    IEnumerable<string> rules = o2["Definitions"][0]["MatchExpressions"].Select(x => x["Name"].ToString().Split('/')[1]).Distinct();

                    Assembly assembly = typeof(ValidatorBase).Assembly;
                    // Not all validators are subclasses of ValidatorBase, so for the time being, we'll have to identify them by name
                    HashSet<string> validators = assembly.GetTypes().Where(x => x.Name.EndsWith("Validator")).Select(x => x.Name).ToHashSet();

                    List<string> rulesWithoutValidators = new List<string>();

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
            }
            catch (IOException)
            {
                Assert.True(false, "Failed to read the rules file.");
            }
            catch (NullReferenceException)
            {
                Assert.True(false, "Unexpected JSON structure in rules file");
            }
        }
    }
}
