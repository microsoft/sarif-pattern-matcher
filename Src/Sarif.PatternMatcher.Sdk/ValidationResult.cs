// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public class ValidationResult
    {
        public string Message { get; set; }

        public Fingerprint Fingerprint { get; set; }

        public ResultLevelKind ResultLevelKind { get; set; }

        public ValidationState ValidationState { get; set; }

        /// <summary>
        /// Gets or sets the FlexMatch that describes the result SARIF region.
        /// </summary>
        public FlexMatch RegionFlexMatch { get; set; }

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

        public static IEnumerable<ValidationResult> ContinueProcessing()
        {
            return new[]
            {
                new ValidationResult
                {
                    ValidationState = ValidationState.Unknown,
                },
            };
        }
    }
}
