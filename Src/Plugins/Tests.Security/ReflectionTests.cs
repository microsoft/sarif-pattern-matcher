// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class ReflectionTests
    {
        [Fact]
        public void All101Rules_ShouldHaveValidators()
        {
            try
            {
                using (StreamReader file = File.OpenText(@"SEC101.SecurePlaintextSecrets.json"))
                using (JsonTextReader reader = new JsonTextReader(file))
                {
                    JObject o2 = (JObject)JToken.ReadFrom(reader);
                }
            }
            catch (IOException ioe)
            {
                Assert.True(false, "Failed to read the rules file.");
            }
            
        }
    }
}
