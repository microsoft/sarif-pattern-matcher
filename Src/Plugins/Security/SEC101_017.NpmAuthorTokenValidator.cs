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

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class NpmAuthorTokenValidator : DynamicValidatorBase
    {
        internal const string Uri = "https://registry.npmjs.com/-/npm/v1/tokens";

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch secret = groups["secret"];

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
            string secret = fingerprint.Secret;
            try
            {
                HttpClient client = CreateOrRetrieveCachedHttpClient();

                using var request = new HttpRequestMessage(HttpMethod.Get, Uri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);

                using HttpResponseMessage response = client
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return CheckInformation(response.Content.ReadAsStringAsync().GetAwaiter().GetResult(), secret, ref message, ref resultLevelKind);
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

        private static ValidationState CheckInformation(string content, string secret, ref string message, ref ResultLevelKind resultLevelKind)
        {
            TokensRoot tokensRoot = JsonConvert.DeserializeObject<TokensRoot>(content);
            if (tokensRoot?.Tokens?.Count > 0)
            {
                foreach (Object obj in tokensRoot.Tokens)
                {
                    if (!secret.Contains(obj.Token))
                    {
                        continue;
                    }

                    if (obj.Readonly)
                    {
                        message = "The token has 'read' permissions.";
                        resultLevelKind = new ResultLevelKind { Level = FailureLevel.Warning };
                        return ValidationState.Authorized;
                    }

                    if (obj.Automation)
                    {
                        message = "The token has 'automation' permissions.";
                        return ValidationState.Authorized;
                    }

                    message = "The token has 'publish' permissions.";
                    return ValidationState.Authorized;
                }
            }

            return ValidationState.Authorized;
        }

        internal class Object
        {
            [JsonProperty("token")]
            public string Token { get; set; }

            [JsonProperty("key")]
            public string Key { get; set; }

            [JsonProperty("cidr_whitelist")]
            public object CidrWhitelist { get; set; }

            [JsonProperty("readonly")]
            public bool Readonly { get; set; }

            [JsonProperty("automation")]
            public bool Automation { get; set; }

            [JsonProperty("created")]
            public DateTime Created { get; set; }

            [JsonProperty("updated")]
            public DateTime Updated { get; set; }
        }

        internal class TokensRoot
        {
            [JsonProperty("objects")]
            public List<Object> Tokens { get; set; }

            [JsonProperty("total")]
            public int Total { get; set; }
        }
    }
}
