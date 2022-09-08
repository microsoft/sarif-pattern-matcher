// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public abstract class StaticValidatorBase : ValidatorBase
    {
        public IEnumerable<ValidationResult> IsValidStatic(IDictionary<string, FlexMatch> groups)
        {
            IEnumerable<ValidationResult> validationResults = IsValidStaticHelper(groups);

            foreach (ValidationResult validationResult in validationResults)
            {
                if (validationResult.ValidationState == ValidationState.NoMatch)
                {
                    continue;
                }

                string scanTarget = groups["scanTargetFullPath"].Value;
                string key = $"{scanTarget}#{validationResult.Fingerprint}";

                if (PerFileFingerprintCache != null)
                {
                    if (PerFileFingerprintCache.ContainsKey(key))
                    {
                        validationResult.ValidationState = ValidationState.NoMatch;
                        continue;
                    }

                    PerFileFingerprintCache.Add(key, (byte)0);
                }
            }

            return validationResults;
        }

        public void DisablePerFileFingerprintCache(bool disablePerFileFingerprintCache)
        {
            PerFileFingerprintCache = disablePerFileFingerprintCache
                ? null
                : new ConcurrentDictionary<string, byte>();
        }

        /// <summary>
        /// Validate if the match is a secret or credential.
        /// </summary>
        /// <param name="groups">
        /// Capture groups from the regex match. Dictionary entries can be modified or new entries
        /// added in order to refine or add argument values that will be used in result messages.
        /// </param>
        ///
        /// <returns>Return an enumerable ValidationResult collection.</returns>
        protected abstract IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups);
    }
}
