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

        [Fact]
        public void ExtenstionMethods_ContainUpperLowerAndDigitShouldBeAccurate()
        {
            string lowercaseOnly = "onlylowercase";
            lowercaseOnly.ContainsDigitAndLetter().Should().BeFalse();
            lowercaseOnly.ContainsLowercaseAndUppercaseLetter().Should().BeFalse();
            lowercaseOnly.ContainsLowercaseAndUppercaseAndDigit().Should().BeFalse();

            string uppercaseOnly = "ONLYUPPERCASE";
            uppercaseOnly.ContainsDigitAndLetter().Should().BeFalse();
            uppercaseOnly.ContainsLowercaseAndUppercaseLetter().Should().BeFalse();
            uppercaseOnly.ContainsLowercaseAndUppercaseAndDigit().Should().BeFalse();

            string digitsOnly = "0123456789";
            digitsOnly.ContainsDigitAndLetter().Should().BeFalse();
            digitsOnly.ContainsLowercaseAndUppercaseLetter().Should().BeFalse();
            digitsOnly.ContainsLowercaseAndUppercaseAndDigit().Should().BeFalse();

            string symbolsAndDigits = "!@#$%^&*(()0123467";
            symbolsAndDigits.ContainsDigitAndLetter().Should().BeFalse();
            symbolsAndDigits.ContainsLowercaseAndUppercaseLetter().Should().BeFalse();
            symbolsAndDigits.ContainsLowercaseAndUppercaseAndDigit().Should().BeFalse();

            string lowerAndUppercase = "lowercaseUPPERCASE";
            lowerAndUppercase.ContainsDigitAndLetter().Should().BeFalse();
            lowerAndUppercase.ContainsLowercaseAndUppercaseLetter().Should().BeTrue();
            lowerAndUppercase.ContainsLowercaseAndUppercaseAndDigit().Should().BeFalse();

            string lowercaseAndDigits = "lowercase0123456";
            lowercaseAndDigits.ContainsDigitAndLetter().Should().BeTrue();
            lowercaseAndDigits.ContainsLowercaseAndUppercaseLetter().Should().BeFalse();
            lowercaseAndDigits.ContainsLowercaseAndUppercaseAndDigit().Should().BeFalse();

            string uppercaseAndDigits = "UPPERCASE0123456";
            uppercaseAndDigits.ContainsDigitAndLetter().Should().BeTrue();
            uppercaseAndDigits.ContainsLowercaseAndUppercaseLetter().Should().BeFalse();
            uppercaseAndDigits.ContainsLowercaseAndUppercaseAndDigit().Should().BeFalse();

            string lowerUpperDigits = "lowerUPPER0123456";
            lowerUpperDigits.ContainsDigitAndLetter().Should().BeTrue();
            lowerUpperDigits.ContainsLowercaseAndUppercaseLetter().Should().BeTrue();
            lowerUpperDigits.ContainsLowercaseAndUppercaseAndDigit().Should().BeTrue();

            string shortString = "eM3";
            shortString.ContainsDigitAndLetter().Should().BeTrue();
            shortString.ContainsLowercaseAndUppercaseLetter().Should().BeTrue();
            shortString.ContainsLowercaseAndUppercaseAndDigit().Should().BeTrue();
        }
    }
}
