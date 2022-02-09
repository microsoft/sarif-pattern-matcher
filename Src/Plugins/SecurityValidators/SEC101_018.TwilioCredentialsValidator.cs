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

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators
{
    public class TwilioCredentialsValidator : DynamicValidatorBase
    {
        internal const string TestCredentialMessage = "Resource not accessible with Test Account Credentials";

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
                    Platform = nameof(AssetPlatform.Twilio),
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

            const string uri = "https://api.twilio.com/2010-04-01/Accounts.json";

            try
            {
                string credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", id, secret)));
                HttpClient httpClient = CreateOrRetrieveCachedHttpClient();
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

                using HttpResponseMessage response = httpClient
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return ReturnAuthorizedAccess(ref message, asset: id);
                    }

                    case HttpStatusCode.Unauthorized:
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: id);
                    }

                    case HttpStatusCode.Forbidden:
                    {
                        string content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        if (!string.IsNullOrEmpty(content)
                            && content.Contains(TestCredentialMessage))
                        {
                            resultLevelKind = new ResultLevelKind { Level = FailureLevel.Warning };
                            return ReturnAuthorizedAccess(ref message, asset: id);
                        }

                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode, asset: id);
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode, asset: id);
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
