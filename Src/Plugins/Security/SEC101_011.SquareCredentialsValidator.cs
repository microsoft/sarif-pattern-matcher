// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class SquareCredentialsValidator : ValidatorBase
    {
        internal static SquareCredentialsValidator Instance;

        static SquareCredentialsValidator()
        {
            Instance = new SquareCredentialsValidator();
        }

        public static IEnumerable<ValidationResult> IsValidStatic(Dictionary<string, FlexMatch> groups)
        {
            return IsValidStatic(Instance, groups);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     Dictionary<string, string> options,
                                                     ref ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  options,
                                  ref resultLevelKind);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(Dictionary<string, FlexMatch> groups)
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
                                                                Dictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string id = fingerprint.Id;
            string secret = fingerprint.Secret;

            const string uri = "https://connect.squareup.com/oauth2/token";
            const string CodeNotFoundMessage = "Authorization code not found";
            const string CodeForRequest = "123";

            try
            {
                HttpClient client = CreateHttpClient();

                var dict = new Dictionary<string, string>();
                dict.Add("grant_type", "authorization_code");
                dict.Add("code", CodeForRequest); // Needs some value for call to work.
                dict.Add("client_id", id);
                dict.Add("client_secret", secret);

                using var request = new HttpRequestMessage(HttpMethod.Post, uri);
                request.Content = new FormUrlEncodedContent(dict);

                using HttpResponseMessage response = client
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                string res = response.Content.ReadAsStringAsync().Result; // Actually runs synchronously when "Result" is called.

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return ValidationState.Authorized; // This should theoretically never be hit, a "code" of 123 is much too short. But if we do get a 200, it's a valid Credential.
                    }

                    case HttpStatusCode.Unauthorized:
                    {
                        if (res.Contains(CodeNotFoundMessage))
                        {
                            // Credential was valid, code was not.
                            return ValidationState.Authorized;
                        }

                        // Credential not valid.
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
