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

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class NpmCredentialsValidator : DynamicValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("host", out FlexMatch host) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            if (!ContainsDigitAndChar(secret.Value))
            {
                return ValidationResult.CreateNoMatch();
            }

            groups.TryGetNonEmptyValue("id", out FlexMatch id);

            string decodedId;
            string decodedPassword;

            try
            {
                byte[] data = Convert.FromBase64String(secret.Value);
                decodedPassword = Encoding.UTF8.GetString(data);

                if (decodedPassword.Contains(':'))
                {
                    string[] parts = decodedPassword.Split(':');
                    decodedId = parts[0];
                    decodedPassword = parts[1];
                }
                else
                {
                    decodedId = id?.Value;
                    decodedPassword = secret.Value;
                }
            }
            catch (FormatException)
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Id = decodedId,
                    Host = host.Value,
                    Secret = decodedPassword,
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
            string id = fingerprint.Id;
            string host = fingerprint.Host;
            string secret = fingerprint.Secret;
            string uri = $"https://{host}";

            HttpClient client = CreateOrRetrieveCachedHttpClient();

            try
            {
                using var requestWithNoCredentials = new HttpRequestMessage(HttpMethod.Get, uri);
                using HttpResponseMessage responseWithNoCredentials = client
                    .SendAsync(requestWithNoCredentials, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                if (responseWithNoCredentials.StatusCode == HttpStatusCode.OK ||
                    responseWithNoCredentials.StatusCode == HttpStatusCode.NotFound ||
                    responseWithNoCredentials.StatusCode == HttpStatusCode.NonAuthoritativeInformation)
                {
                    return ValidationState.NoMatch;
                }

                string credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", id, secret)));

                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

                using HttpResponseMessage responseWithCredentials = client
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (responseWithCredentials.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return ReturnAuthorizedAccess(ref message, host, account: id);
                    }

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
