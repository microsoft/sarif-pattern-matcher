// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class MySqlConnectionStringValidatorTests
    {
        [Fact]
        public void MySqlConnectionStringValidator_Test()
        {
            string fingerprintText = "";
            if (string.IsNullOrEmpty(fingerprintText))
            {
                return;
            }

            string message = null;
            var fingerprint = new Fingerprint(fingerprintText);
            var keyValuePairs = new Dictionary<string, string>();

            MySqlConnectionStringValidator.IsValidDynamic(ref fingerprint, ref message, ref keyValuePairs);
        }
    }
}
