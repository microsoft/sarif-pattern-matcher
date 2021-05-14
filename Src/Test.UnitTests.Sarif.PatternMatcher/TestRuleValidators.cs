// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    /// <summary>
    /// This is test validator used for unit test.
    /// </summary>
    public class OverrideIndexTestValidator
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0060:Remove unused parameter", Justification = "<Pending>")]
        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  Dictionary<string, string> groups)
        {
            // "TestTerm Another-TEST-TERM"
            // original index is 0, override it to 17, length to 9
            var result = new ValidationResult
            {
                ValidationState = ValidationState.Unknown,
                ResultLevelKind = new ResultLevelKind { Kind = ResultKind.Fail, Level = FailureLevel.Warning },
                OverrideIndex = 17,
                OverrideLength = 9,
            };

            return new[] { result };
        }
    }

    /// <summary>
    /// This is test validator used for unit test.
    /// </summary>
    public class DoesNotOverrideTestValidator
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0060:Remove unused parameter", Justification = "<Pending>")]
        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                          Dictionary<string, string> groups)
        {
            var result = new ValidationResult
            {
                ValidationState = ValidationState.Unknown,
            };

            return new[] { result };
        }
    }

    /// <summary>
    /// This is test validator used for unit test.
    /// </summary>
    public class VerifyResultKindLevelTestValidator
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0060:Remove unused parameter", Justification = "<Pending>")]
        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                          Dictionary<string, string> groups)
        {
            // result multiple results
            ValidationResult[] results = new[]
            {
                new ValidationResult
                {
                    ValidationState = ValidationState.Authorized, // expect FailureLevel.Error
                },
                new ValidationResult
                {
                    ValidationState = ValidationState.PasswordProtected, // expect FailureLevel.Warning
                },
                new ValidationResult
                {
                    ValidationState = ValidationState.Unauthorized, // expect FailureLevel.Note
                },
                new ValidationResult
                {
                    ValidationState = ValidationState.Expired, // expect FailureLevel.Note
                },
                new ValidationResult
                {
                    ValidationState = ValidationState.UnknownHost, // expect FailureLevel.Note
                },
                new ValidationResult
                {
                    ValidationState = ValidationState.InvalidForConsultedAuthorities, // expect FailureLevel.Note
                },
                new ValidationResult
                {
                    ValidationState = ValidationState.Unknown, // expect FailureLevel.Note
                },
                new ValidationResult
                {
                    ValidationState = ValidationState.ValidatorNotFound, // expect FailureLevel.Note
                },
            };

            return results;
        }
    }

    /// <summary>
    /// This is test validator used for unit test.
    /// </summary>
    public class InvalidIndexLengthTestValidator
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0060:Remove unused parameter", Justification = "<Pending>")]
        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                          Dictionary<string, string> groups)
        {
            // matchedPatrtern "TestTerm Another-TEST-TERM", length is 26
            ValidationResult[] results = new[]
            {
                new ValidationResult
                {
                    ValidationState = ValidationState.Unknown,
                    ResultLevelKind = new ResultLevelKind { Level = FailureLevel.Error },
                    OverrideIndex = -1, // result region will be the from 0 to end of string
                },
                new ValidationResult
                {
                    ValidationState = ValidationState.Unknown,
                    ResultLevelKind = new ResultLevelKind { Level = FailureLevel.Error },
                    OverrideIndex = 26, // result region will be the from 0 to end of string
                },
                new ValidationResult
                {
                    ValidationState = ValidationState.Unknown,
                    ResultLevelKind = new ResultLevelKind { Level = FailureLevel.Error },
                    OverrideIndex = 17,
                    OverrideLength = 100, // result region will be the from override index to end of string
                },
            };

            return results;
        }
    }
}
