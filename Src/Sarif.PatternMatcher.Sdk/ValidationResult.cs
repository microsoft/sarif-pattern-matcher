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

        /// <summary>
        /// Gets or sets the override index of match found in matched pattern by validator.
        /// </summary>
        public int? OverrideIndex { get; set; }

        /// <summary>
        /// Gets or sets the override length of match found in matched pattern by validator.
        /// </summary>
        public int? OverrideLength { get; set; }

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
