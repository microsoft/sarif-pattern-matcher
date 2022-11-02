// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net.Http;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;
using Microsoft.Security.Utilities;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class NpmAuthorIdentifiableTokenValidator : DynamicValidatorBase
    {
        private readonly CustomAlphabetEncoder encoder = new CustomAlphabetEncoder();

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch secret = groups["secret"];
            FlexMatch checksum = groups["checksum"];

            // Validate checksum to avoid false positives.
            string randomPart = secret.Value.String.Substring(4, 30);
            uint checksumValue = Crc32.Calculate(randomPart);
            string encodedChecksum = encoder.Encode(checksumValue);

            if (checksum.Value != encodedChecksum)
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.Npm),
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            HttpClient client = CreateOrRetrieveCachedHttpClient();

            return NpmAuthorTokenHelper.ValidateTokens(ref fingerprint,
                                                       ref message,
                                                       ref resultLevelKind,
                                                       client);
        }
    }
}
