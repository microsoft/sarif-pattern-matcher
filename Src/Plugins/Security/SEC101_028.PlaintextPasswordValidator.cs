// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class PlaintextPasswordValidator : ValidatorBase
    {
        internal static PlaintextPasswordValidator Instance;

        static PlaintextPasswordValidator()
        {
            Instance = new PlaintextPasswordValidator();
        }

        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  ref Dictionary<string, string> groups,
                                                                  ref string message)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref message);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(ref string matchedPattern,
                                                                             ref Dictionary<string, string> groups,
                                                                             ref string message)
        {
            if (!groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationResult.NoMatch;
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Secret = secret,
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
