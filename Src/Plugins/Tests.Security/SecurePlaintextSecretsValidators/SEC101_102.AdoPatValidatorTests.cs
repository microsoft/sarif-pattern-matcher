// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    /// <summary>
    /// Testing SEC101/102.AdoPatValidator
    /// </summary>
    public class AdoPatValidatorTests
    {
        private struct TestCase
        {
            public string Title;
            public string Secret;
            public int ExpectedValidationResults;
            public ValidationState ExpectedValidationState;
        }

        private static readonly TestCase[] s_coreTestCases = new[]
        {
            new TestCase
            {
                Title = "NoMatch due to invalid PAT CRC.",
                Secret = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead",
                ExpectedValidationResults = 1,
                ExpectedValidationState = ValidationState.NoMatch
            }
        };

        [Fact]
        public void AzureDevOpsPersonalAccessTokenValidator_IsValidBasic()
        {
            var failedTestCases = new List<string>();
            var adoPatValidator = new AdoPatValidator();
            foreach (TestCase testCase in s_coreTestCases)
            {
                var groups = new Dictionary<string, FlexMatch>
                {
                    { "secret", new FlexMatch { Value = testCase.Secret } }
                };

                IEnumerable<ValidationResult> validationResults = adoPatValidator.IsValidStatic(groups);

                string title = testCase.Title;

                Verify(validationResults.Count() == testCase.ExpectedValidationResults, title, failedTestCases);

                foreach (ValidationResult validationResult in validationResults)
                {
                    Verify(validationResult.ValidationState == testCase.ExpectedValidationState, title, failedTestCases);
                }
            }

            failedTestCases.Should().BeEmpty();
        }

        private static void Verify(bool condition, string title, List<string> failedTestCases)
        {
            if (!condition)
            {
                failedTestCases.Add($"{Environment.NewLine}{title}");
            }
        }
    }
}
