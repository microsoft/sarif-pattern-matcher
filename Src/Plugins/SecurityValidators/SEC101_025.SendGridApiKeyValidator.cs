// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators
{
    public class SendGridApiKeyValidator : DynamicValidatorBase
    {
        internal const string ApiUri = "https://api.sendgrid.com/v3/scopes";

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch secret = groups["secret"];

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.SendGrid),
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

            try
            {
                HttpClient httpClient = CreateOrRetrieveCachedHttpClient();

                using var request = new HttpRequestMessage(HttpMethod.Get, ApiUri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);

                using HttpResponseMessage response = httpClient
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        string content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                        ScopeResponse scope = JsonConvert.DeserializeObject<ScopeResponse>(content);
                        if (scope?.Scopes?.Count > 0)
                        {
                            message = $"The secret has the '{string.Join(",", scope.Scopes)}' permission(s).";
                        }

                        return ValidationState.Authorized;
                    }

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

        internal class ScopeResponse
        {
            [JsonProperty("scopes")]
            public List<string> Scopes { get; set; }
        }
    }
}
