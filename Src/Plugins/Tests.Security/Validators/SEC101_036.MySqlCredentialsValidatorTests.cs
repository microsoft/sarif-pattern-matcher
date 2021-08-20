// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class MySqlCredentialsValidatorTests
    {
        [Fact]
        public void MySqlCredentialsValidator_Test()
        {
            string fingerprintText = "";
            if (string.IsNullOrEmpty(fingerprintText))
            {
                return;
            }

            string message = null;
            ResultLevelKind resultLevelKind = default;
            var fingerprint = new Fingerprint(fingerprintText);
            var keyValuePairs = new Dictionary<string, string>();

            var mySqlCredentialsValidator = new MySqlCredentialsValidator();
            mySqlCredentialsValidator.IsValidDynamic(ref fingerprint,
                                                     ref message,
                                                     keyValuePairs,
                                                     ref resultLevelKind);
        }
    }
}
