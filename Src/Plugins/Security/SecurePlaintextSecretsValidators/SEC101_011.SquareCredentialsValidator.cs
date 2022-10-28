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
    public class SquareCredentialsValidator : DynamicValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Id = id.Value,
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.Square),
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
            string id = fingerprint.Id;
            string secret = fingerprint.Secret;

            const string codeForRequest = "123";
            const string uri = "https://connect.squareup.com/oauth2/token";
            const string codeNotFoundMessage = "Authorization code not found";

            try
            {
                HttpClient client = CreateOrRetrieveCachedHttpClient();

                var dict = new Dictionary<string, string>()
                {
                    { "client_id", id },
                    { "code", codeForRequest },
                    { "client_secret", secret },
                    { "grant_type", "authorization_code" },
                };

                using var request = new HttpRequestMessage(HttpMethod.Post, uri);
                request.Content = new FormUrlEncodedContent(dict);

                using HttpResponseMessage response = client
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.Unauthorized:
                    {
                        string content = response.Content
                                                 .ReadAsStringAsync()
                                                 .GetAwaiter()
                                                 .GetResult();

                        if (content.Contains(codeNotFoundMessage))
                        {
                            // Credential was valid, code was not.
                            return ReturnAuthorizedAccess(ref message, id);
                        }

                        // Credential not valid.
                        return ReturnUnauthorizedAccess(ref message, id);
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
