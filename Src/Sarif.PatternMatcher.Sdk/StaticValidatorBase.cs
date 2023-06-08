// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public abstract class StaticValidatorBase : ValidatorBase
    {
        protected virtual string Platform { get; set; }

        /// <summary>
        /// Examines the groups output by a positive regex match and
        /// optionally performs additional validation to determine
        /// whether the match is valid.
        /// </summary>
        /// <param name="groups">
        /// The named groups resulting from a positive regex match. This
        /// data also transports a certain number of injected well-known
        /// named values (such as the file name of the scan target).
        /// </param>
        /// <param name="perFileFingerprintCache">
        /// A cache of file + fingerprint combinations that have been
        /// observed previously. Our scanner will only detect and validate
        /// a unique fingerprint once per file. Many regexes will produce
        /// multiple matches that resolve to the same unique credential in
        /// a file (one of the perils of multiline regex matching). It is
        /// possible that this cache may drop the location of a second
        /// actual match that happens to be duplicated in the file. In
        /// practice, we will not worry about this scenario: it will be
        /// sufficient that we flag one instance of the unique secret.
        /// </param>
        /// <returns> One or ValidationResults indicating zero or more valid findings.
        /// </returns>
        public IEnumerable<ValidationResult> IsValidStatic(IDictionary<string, FlexMatch> groups,
                                                           ISet<string> perFileFingerprintCache)
        {
            IEnumerable<ValidationResult> validationResults = IsValidStaticHelper(groups);

            foreach (ValidationResult validationResult in validationResults)
            {
                if (validationResult.ValidationState == ValidationState.NoMatch)
                {
                    continue;
                }

                string fingerprintText = $"{validationResult.Fingerprint}";

                if (perFileFingerprintCache.Contains(fingerprintText))
                {
                    validationResult.ValidationState = ValidationState.NoMatch;
                }

                perFileFingerprintCache.Add(fingerprintText);
            }

            return validationResults;
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
        protected virtual IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            string secret = groups["secret"].Value;

            if (IsFalsePositiveOrBelongsToOtherSecurityModel(secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Secret = secret,
                    Platform = Platform ?? throw new ArgumentNullException(nameof(Platform)),
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }

        /// <summary>
        /// Evaluates secret to determine whether is a false positive or if it perhaps
        /// is a true positive but one that belongs to another security model.
        /// </summary>
        /// <param name="secret">Text for a secret to be evaluated for accuracy and associated with current security model.</param>
        /// <returns>'True' if the secret should be excluded from current analysis, otheriwise 'false'.</returns>
        protected virtual bool IsFalsePositiveOrBelongsToOtherSecurityModel(string secret)
        {
            return false;
        }
    }
}
