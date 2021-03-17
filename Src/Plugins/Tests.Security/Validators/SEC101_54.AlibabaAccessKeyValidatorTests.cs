// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class AlibabaAccessKeyValidatorTests
    {
        private readonly string _expectedValidationState = nameof(ValidationState.NoMatch);
        private readonly string _accessKeyId = "LTAI01234567890123456789";
        private readonly string _accessKeySecret = "111111111101234567890123456789";

        [Fact]
        public void DummyCredentials_ShouldHaveInvalidTest()
        {
            string fingerprintText = string.Format("[acct={0}][pwd={1}]", _accessKeyId, _accessKeySecret);
            string message = null;
            Dictionary<string, string> keyValuePairs = new Dictionary<string, string>();

            string actualValidationState = AlibabaAccessKeyValidator.IsValidDynamic(ref fingerprintText, ref message, ref keyValuePairs);
            Assert.Equal(_expectedValidationState, actualValidationState);
        }
    }
}
