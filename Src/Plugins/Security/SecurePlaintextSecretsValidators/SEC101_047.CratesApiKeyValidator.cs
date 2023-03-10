// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class CratesApiKeyValidator : DynamicValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch secret = groups["secret"];

            if (!secret.Value.ToString().ContainsDigitAndLetter())
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.Crates),
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
            string secret = fingerprint.Secret;

            const string uri = "https://crates.io/api/v1/crates/sarif-pattern-matcher/owners";

            try
            {
                HttpClient client = CreateOrRetrieveCachedHttpClient();

                using var request = new HttpRequestMessage(HttpMethod.Delete, uri);
                request.Headers.Add("Authorization", secret);

                using HttpResponseMessage response = client
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return ValidationState.Authorized;
                    }

                    case HttpStatusCode.Forbidden:
                    case HttpStatusCode.Unauthorized:
                    {
                        return ValidationState.Unauthorized;
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e);
            }
        }
    }
}
