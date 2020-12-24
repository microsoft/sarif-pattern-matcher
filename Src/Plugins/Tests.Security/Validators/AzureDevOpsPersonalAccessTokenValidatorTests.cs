// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Security
{
    public class AzureDevOpsPersonalAccessTokenValidatorTests
    {
        [Theory]
        [InlineData("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead", "NoMatch")]
        public void CheckIsValid(string input, string expected)
        {
            bool performDynamicValidation = false;
            string failureLevel = "error";
            string result = AzureDevOpsPersonalAccessTokenValidator.IsValid(input, ref performDynamicValidation, ref failureLevel);
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("a")]
        [InlineData("")]
        public void CheckInvalidInput(string input)
        {
            bool performDynamicValidation = false;
            string failureLevel = "error";
            Assert.Throws<ArgumentException>(() => AzureDevOpsPersonalAccessTokenValidator.IsValid(input, ref performDynamicValidation, ref failureLevel));
        }
    }
}
