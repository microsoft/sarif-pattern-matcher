// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class IdentifiableNpmAuthorTokenValidator : DynamicValidatorBase
    {
        [ThreadStatic]
        private static StringBuilder s_sb;

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch secret = groups["secret"];

            if (groups.TryGetNonEmptyValue("checksum", out FlexMatch checksum))
            {
                string randomPart = secret.Value.String.Substring(4, 30);
                uint checksumValue = Crc32.Calculate(randomPart);
                string encodedChecksum = Base62EncodeUint32(checksumValue);

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

            return ValidationResult.CreateNoMatch();
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

        private static string Base62EncodeUint32(uint value, int minimumLength = 6)
        {
            const string primitives = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

            if (value <= 0)
            {
                return new string(primitives[0], minimumLength);
            }

            s_sb ??= new StringBuilder();
            s_sb.Clear();

            while (value > 0)
            {
                s_sb.Append(primitives[(int)(value % 62)]);
                value /= 62;
            }

            string result = new string(s_sb.ToString().Reverse().ToArray());

            return result.Length >= minimumLength
                    ? result
                    : new string(primitives[0], minimumLength - s_sb.Length) + result;
        }
    }
}
