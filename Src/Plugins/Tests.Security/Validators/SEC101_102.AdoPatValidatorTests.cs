// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

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
                string fingerprintText = null, message = null;
                var groups = new Dictionary<string, string>();
                Fingerprint fingerprint;

                ValidationState state =
                    AdoPatValidator.IsValidStatic(ref testCase.Input,
                                                  ref groups,
                                                  ref failureLevel,
                                                  ref message,
                                                  out fingerprint);

                string title = testCase.Title;

                Verify(state == testCase.ExpectedValidationState, title, failedTestCases);

                Verify(failureLevel == testCase.FailureLevel, title, failedTestCases);
                Verify(state == testCase.ExpectedValidationState, title, failedTestCases);

                if (state != ValidationState.Unknown)
                {
                    Verify(fingerprintText == null, title, failedTestCases);
                }
                else
                {
                    Verify(fingerprintText == $"[pat/vs={testCase.Input}]", title, failedTestCases);
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
