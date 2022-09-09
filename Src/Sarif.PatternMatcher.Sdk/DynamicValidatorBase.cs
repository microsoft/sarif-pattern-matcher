// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public abstract class DynamicValidatorBase : StaticValidatorBase
    {
        public ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                              ref string message,
                                              IDictionary<string, string> options,
                                              ref ResultLevelKind resultLevelKind)
        {
            resultLevelKind = default;

            if (shouldUseDynamicCache &&
                FingerprintToResultCache != null &&
                FingerprintToResultCache.TryGetValue(fingerprint, out Tuple<ValidationState, ResultLevelKind, string> result))
            {
                message = result.Item3;
                resultLevelKind = result.Item2;
                return result.Item1;
            }

            ValidationState validationState = IsValidDynamicHelper(ref fingerprint,
                                                                   ref message,
                                                                   options,
                                                                   ref resultLevelKind);

            if (FingerprintToResultCache != null)
            {
                FingerprintToResultCache[fingerprint] =
                    new Tuple<ValidationState, ResultLevelKind, string>(validationState, resultLevelKind, message);
            }

            return validationState;
        }

        protected virtual ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                               ref string message,
                                                               IDictionary<string, string> options,
                                                               ref ResultLevelKind resultLevelKind)
        {
            return ValidationState.NoMatch;
        }
    }
}
