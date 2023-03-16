// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public abstract class DynamicValidatorBase : StaticValidatorBase
    {
        public virtual bool DynamicAnalysisImplemented => true;

        public ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                              ref string message,
                                              IDictionary<string, string> options,
                                              ref ResultLevelKind resultLevelKind)
        {
            resultLevelKind = default;

            if (shouldUseDynamicCache &&
                FingerprintToResultCache.TryGetValue(fingerprint, out Tuple<ValidationState, ResultLevelKind, string> result))
            {
                message = result.Item3;
                resultLevelKind = result.Item2;
                return result.Item1;
            }

            Tuple<ValidationState, Fingerprint, string, ResultLevelKind> dynamicValidationResponse = await IsValidDynamicHelper(fingerprint,
                                                                   message,
                                                                   options,
                                                                   resultLevelKind);

            FingerprintToResultCache[fingerprint] =
                new Tuple<ValidationState, ResultLevelKind, string>(validationState, resultLevelKind, message);

            return validationState;
        }

        protected virtual async Task<ValidationState> IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                               ref string message,
                                                               IDictionary<string, string> options,
                                                               ref ResultLevelKind resultLevelKind)
        {
            return ValidationState.NoMatch;
        }
    }
}
