// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class AdoPatValidatorTests
    {
        internal class TestCase
        {
            public string Title;
            public string Input;
            public ValidationState ExpectedValidationState;
            public bool PerformDynamicValidation;
            public string FailureLevel;
        }

        internal static TestCase[] s_coreTestCases = new[]
        {
            new TestCase
            {
                Title = "NoMatch due to invalid PAT CRC, no dynamic validation requested.",
                Input = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead",
                ExpectedValidationState = ValidationState.NoMatch,
                FailureLevel = "Error",
            },
            new TestCase
            {
                Title = "NoMatch due to invalid PAT CRC, dynamic validation requested.",
                Input = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead",
                ExpectedValidationState = ValidationState.NoMatch,
                FailureLevel = "Warning",
                PerformDynamicValidation = true
            }
        };

        [Fact]
        public void AzureDevOpsPersonalAccessTokenValidator_IsValidBasic()
        {
            var failedTestCases = new List<string>();

            foreach (TestCase testCase in s_coreTestCases)
            {
                bool performDynamicValidation = testCase.PerformDynamicValidation;
                string failureLevel = testCase.FailureLevel;
                string fingerprintText = null;
                var groups = new Dictionary<string, FlexMatch>();

                IEnumerable<ValidationResult> validationResults = AdoPatValidator.IsValidStatic(groups);

                string title = testCase.Title;

                foreach (ValidationResult validationResult in validationResults)
                {
                    Verify(validationResult.ValidationState == testCase.ExpectedValidationState, title, failedTestCases);

                    Verify(failureLevel == testCase.FailureLevel, title, failedTestCases);
                    Verify(validationResult.ValidationState == testCase.ExpectedValidationState, title, failedTestCases);

                    if (validationResult.ValidationState != ValidationState.Unknown)
                    {
                        Verify(fingerprintText == null, title, failedTestCases);
                    }
                    else
                    {
                        Verify(fingerprintText == $"[pat/vs={testCase.Input}]", title, failedTestCases);
                    }
                }
            }

            failedTestCases.Should().BeEmpty();
        }

        private void Verify(bool condition, string title, List<string> failedTestCases)
        {
            if (!condition)
            {
                failedTestCases.Add($"{Environment.NewLine}{title}");
            }
        }
    }
}
