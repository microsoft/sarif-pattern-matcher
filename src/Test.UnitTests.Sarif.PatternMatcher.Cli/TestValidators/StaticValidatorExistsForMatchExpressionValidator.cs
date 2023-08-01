// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli.TestValidators
{
    [ValidatorDescriptor(Id)]
    internal class StaticValidatorExistsForMatchExpressionValidator : StaticValidatorBase
    {
        internal const string Id = "TEST001/002";

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            string secret = groups["0"].Value;

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Platform = nameof(AssetPlatform.Unknown),
                    Secret = secret,
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }
    }
}
