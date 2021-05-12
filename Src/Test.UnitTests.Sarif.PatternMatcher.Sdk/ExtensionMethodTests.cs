// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using FluentAssertions;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public class ExtensionMethodTests
    {
        [Fact]
        public void ExtensionMethods_Truncate()
        {
            var failedTests = new List<string>();

            var testCases = new[]
            {
                new { Input = "", Expected = "", Length = -1},
                new { Input = "1234", Expected = "…", Length = 0},
                new { Input = "1234", Expected = "1234", Length = -1},
                new { Input = (string)null, Expected = "", Length = -1},
                new { Input = "1234", Expected = "12…", Length = 2},
                new { Input = "123456", Expected = "123456", Length = -1},
                new { Input = "1234567", Expected = "123456…", Length = -1},
                new { Input = "1234567890", Expected = "123456…", Length = -1},
            };

            foreach (var testCase in testCases)
            {
                string actual;

                if (testCase.Length == -1)
                {
                    actual = testCase.Input.Truncate();
                }
                else
                {
                    actual = testCase.Input.Truncate(testCase.Length);
                }

                if (!actual.Equals(testCase.Expected))
                {
                    failedTests.Add($"Truncation of '{testCase.Input}' returned '{actual}' rather than '{testCase.Expected}'");
                }
            }

            failedTests.Should().BeEmpty();
        }
    }
}
