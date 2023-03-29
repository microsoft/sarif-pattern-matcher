// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GitHubAppCredentialsValidator : DynamicValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            // It is highly likely we do not have a key if we can't
            // find at least one letter and digit within the pattern.
            if (!secret.Value.ToString().ContainsDigitAndLetter())
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Id = id.Value,
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.GitHub),
                },
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
            const string uri = "https://github.com/login/oauth/access_token";

            try
            {
                HttpClient client = CreateOrRetrieveCachedHttpClient();

                using var request = new HttpRequestMessage(HttpMethod.Post, uri);
                request.Content = new StringContent($@"{{""client_id"": ""{id}"",""client_secret"": ""{secret}""}}", Encoding.UTF8, "application/json");
                request.Headers.Add("User-Agent", "SarifPatternMatcher");

                using HttpResponseMessage response = client.ReadResponseHeaders(request);

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        string content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                        if (content.StartsWith("error=incorrect_client_credentials", StringComparison.OrdinalIgnoreCase))
                        {
                            return ReturnUnauthorizedAccess(ref message, asset: id);
                        }

                        if (content.StartsWith("error=redirect_uri_mismatch", StringComparison.OrdinalIgnoreCase))
                        {
                            return ReturnAuthorizedAccess(ref message, asset: id);
                        }

                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode, asset: id);
                    }

                    case HttpStatusCode.NotFound:
                    {
                        // When you delete the App, you will receive NotFound.
                        return ValidationState.Expired;
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode, asset: id);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: id);
            }
        }
    }
}
