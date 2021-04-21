// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public class ValidationResult
    {
        public string Message { get; set; }

        public Fingerprint Fingerprint { get; set; }

        public ResultLevelKind ResultLevelKind { get; set; }

        public ValidationState ValidationState { get; set; }

        public static IEnumerable<ValidationResult> CreateNoMatch()
        {
            return new[]
            {
                new ValidationResult
                {
                    ValidationState = ValidationState.NoMatch,
                },
            };
        }
    }
}
