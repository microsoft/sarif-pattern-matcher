// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    [ValidatorDescriptor("SEC101/044")]
    public class NpmCredentialsValidator : DynamicValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("host", out FlexMatch host) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            if (!secret.Value.ToString().ContainsDigitAndLetter())
            {
                return ValidationResult.CreateNoMatch();
            }

            groups.TryGetNonEmptyValue("id", out FlexMatch id);
            string user = id?.Value, password = secret.Value;

            try
            {
                byte[] data = Convert.FromBase64String(secret.Value);
                string decodedUserAndPassword = Encoding.UTF8.GetString(data);

                string[] tokens = decodedUserAndPassword.Split(':');

                if (tokens.Length > 2)
                {
                    return ValidationResult.CreateNoMatch();
                }
                else if (tokens.Length == 2)
                {
                    user = tokens[0];
                    password = tokens[1];
                }
                else
                {
                    user = id?.Value;
                    password = tokens[0];
                }
            }
            catch (FormatException)
            {
                // In this code path, we have not received a secret that
                // is a base64-encoded string. And so, we expect the secret
                // is a clear-text password and that we have an 'id' match
                // that tells us the user name.
            }

            if (string.IsNullOrEmpty(user))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Id = user,
                    Host = host.Value,
                    Secret = password,
                    Platform = nameof(AssetPlatform.Npm),
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
            string host = fingerprint.Host;
            string secret = fingerprint.Secret;
            string uri = $"https://{host}";

            HttpClient client = CreateOrRetrieveCachedHttpClient();

            try
            {
                using var requestWithNoCredentials = new HttpRequestMessage(HttpMethod.Get, uri);
                using HttpResponseMessage responseWithNoCredentials = client.ReadResponseHeaders(requestWithNoCredentials);

                if (responseWithNoCredentials.StatusCode == HttpStatusCode.OK ||
                    responseWithNoCredentials.StatusCode == HttpStatusCode.NotFound ||
                    responseWithNoCredentials.StatusCode == HttpStatusCode.NonAuthoritativeInformation)
                {
                    return ValidationState.NoMatch;
                }

                string credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", id, secret)));

                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

                using HttpResponseMessage responseWithCredentials = client.ReadResponseHeaders(request);

                switch (responseWithCredentials.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return ReturnAuthorizedAccess(ref message, host, account: id);
                    }

                    case HttpStatusCode.Forbidden:
                    case HttpStatusCode.Unauthorized:
                    {
                        return ReturnUnauthorizedAccess(ref message, host, account: id);
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, responseWithCredentials.StatusCode, asset: host, account: id);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: host, account: id);
            }
        }
    }
}
