﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GpgCredentialsValidator : ValidatorBase
    {
        internal static GpgCredentialsValidator Instance;

        static GpgCredentialsValidator()
        {
            Instance = new GpgCredentialsValidator();
        }

        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  Dictionary<string, FlexMatch> groups)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 groups);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(ref string matchedPattern,
                                                                             Dictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            groups.TryGetNonEmptyValue("id", out FlexMatch id);

            var validationResult = new ValidationResult
            {
                RegionFlexMatch = secret,
                Fingerprint = new Fingerprint()
                {
                    Id = id?.Value,
                    Secret = secret.Value,
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }
    }
}
