// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text;

using FluentAssertions;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public class ExtensionMethodTests
    {
        [Fact]
        public void ExtensionMethods_Truncate()
        {
            var sb = new StringBuilder();

            var testCases = new[]
            {
                new { Input = "", Expected = "", Length = -1},
                new { Input = "1234", Expected = "…", Length = 0},
                new { Input = "1234", Expected = "1234", Length = -1},
                new { Input = (string)null, Expected = "", Length = -1},
                new { Input = "1234", Expected = "…34", Length = 2},
                new { Input = "123456", Expected = "123456", Length = -1},
                new { Input = "1234567", Expected = "…234567", Length = -1},
                new { Input = "1234567890", Expected = "…567890", Length = -1},
                new { Input = "123456789", Expected = "123456789", Length = 9},
                new { Input = "1234567890", Expected = "…234567890", Length = 9},

                new { Input = "=", Expected = "=", Length = -1},
                new { Input = "1234==", Expected = "…==", Length = 0},
                new { Input = "1234=", Expected = "1234=", Length = -1},
                new { Input = (string)null, Expected = "", Length = -1},
                new { Input = "1234===", Expected = "…34===", Length = 2},
                new { Input = "123456=", Expected = "123456=", Length = -1},
                new { Input = "1234567==", Expected = "…234567==", Length = -1},
                new { Input = "1234567890==", Expected = "…567890==", Length = -1},
                new { Input = "123456789==", Expected = "123456789==", Length = 9},
                new { Input = "1234567890==", Expected = "…234567890==", Length = 9},

                new { Input = "=1234567890==", Expected = "…234567890==", Length = 9},
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
                    sb.AppendLine(
                        $"Truncating '{testCase.Input}' with length " +
                        $"{testCase.Length} returned '{actual}' rather " +
                        $"than '{testCase.Expected}'");
                }
            }

            Assert.True(sb.Length == 0, sb.ToString());
        }

        [Fact]
        public void ExtensionMethods_Anonymize()
        {
            var sb = new StringBuilder();

            char actualRedactionChar = ExtensionMethods.RedactionChar;

            var testCases = new[]
            {
                new { Input = "", Expected = "", Length = -1},
                new { Input = "1234", Expected = "????", Length = 0},
                new { Input = "1234", Expected = "1234", Length = -1},
                new { Input = (string)null, Expected = "", Length = -1},
                new { Input = "1234", Expected = "??34", Length = 2},
                new { Input = "123456", Expected = "123456", Length = -1},
                new { Input = "1234567", Expected = "?234567", Length = -1},
                new { Input = "1234567890", Expected = "????567890", Length = -1},
                new { Input = "123456789", Expected = "123456789", Length = 9},
                new { Input = "1234567890", Expected = "?234567890", Length = 9},

                new { Input = "=", Expected = "=", Length = -1},
                new { Input = "1234==", Expected = "????==", Length = 0},
                new { Input = "1234=", Expected = "1234=", Length = -1},
                new { Input = (string)null, Expected = "", Length = -1},
                new { Input = "1234===", Expected = "??34===", Length = 2},
                new { Input = "123456=", Expected = "123456=", Length = -1},
                new { Input = "1234567==", Expected = "?234567==", Length = -1},
                new { Input = "1234567890==", Expected = "????567890==", Length = -1},
                new { Input = "123456789==", Expected = "123456789==", Length = 9},
                new { Input = "1234567890==", Expected = "?234567890==", Length = 9},

                new { Input = "=1234567890==", Expected = "??234567890==", Length = 9},
            };

            foreach (var testCase in testCases)
            {
                string actual;

                string input = testCase.Input?.Replace('?', actualRedactionChar);

                if (testCase.Length == -1)
                {
                    actual = input.Anonymize();
                }
                else
                {
                    actual = input.Anonymize(testCase.Length);
                }

                if (!actual.Equals(testCase.Expected))
                {
                    sb.AppendLine(
                        $"Anonymizing '{testCase.Input}' with length " +
                        $"{testCase.Length} returned '{actual}' rather " +
                        $"than '{testCase.Expected}'");
                }
            }

            Assert.True(sb.Length == 0, sb.ToString());
        }
    }
}
