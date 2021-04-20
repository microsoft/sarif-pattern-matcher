// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public class ValidationResult
    {
        public static readonly IEnumerable<ValidationResult> NoMatch = new[]
        {
            new ValidationResult
            {
                Fingerprint = default,
                ResultLevelKind = default,
                ValidationState = ValidationState.NoMatch,
            },
        };

        public Fingerprint Fingerprint { get; set; }

        public ResultLevelKind ResultLevelKind { get; set; }

        public ValidationState ValidationState { get; set; }
    }
}
