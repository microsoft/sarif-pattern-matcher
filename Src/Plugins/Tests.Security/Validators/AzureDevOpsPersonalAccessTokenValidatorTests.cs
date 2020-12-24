// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using FluentAssertions;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Security
{
    public class AzureDevOpsPersonalAccessTokenValidatorTests
    {
        [Fact]
        public void CheckIsValid()
        {
            const string input = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead";

            bool performDynamicValidation = false;
            string failureLevel = "error";
            string result = AzureDevOpsPersonalAccessTokenValidator.IsValid(input, ref performDynamicValidation, ref failureLevel);
            Assert.Equal("NoMatch", result);
        }

        [Fact]
        public void CheckInvalidInput()
        {
            var tests = new List<string> { "", "a" };
            var stringBuilder = new StringBuilder();

            bool performDynamicValidation = false;
            string failureLevel = "error";
            foreach (string test in tests)
            {
                try
                {
                    AzureDevOpsPersonalAccessTokenValidator.IsValid(test, ref performDynamicValidation, ref failureLevel);
                    stringBuilder.Append(test).AppendLine(" failed");
                }
                catch (ArgumentException) { }
            }

            stringBuilder.Length.Should().Be(0);
        }
    }
}
