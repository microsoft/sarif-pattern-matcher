// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators
{
    public class PlaintextPasswordValidator : StaticValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch secret = groups["secret"];

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Secret = secret.Value,
                },
                ResultLevelKind = new ResultLevelKind
                {
                    Level = FailureLevel.Warning,
                },
                ValidationState = ValidationState.Authorized,
            };

            return new[] { validationResult };
        }
    }
}
