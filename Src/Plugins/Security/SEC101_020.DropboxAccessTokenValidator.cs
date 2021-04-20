// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class DropboxAccessTokenValidator : ValidatorBase
    {
        internal static DropboxAccessTokenValidator Instance;

        static DropboxAccessTokenValidator()
        {
            Instance = new DropboxAccessTokenValidator();
        }

        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  ref Dictionary<string, string> groups,
                                                                  ref string message)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref message);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     ref Dictionary<string, string> options,
                                                     ref ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options,
                                  ref resultLevelKind);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(ref string matchedPattern,
                                                                             ref Dictionary<string, string> groups,
                                                                             ref string message)
        {
            if (!groups.TryGetNonEmptyValue("refine", out string secret))
            {
                return ValidationResult.NoMatch;
            }

            if (!ContainsDigitAndChar(secret))
            {
                return ValidationResult.NoMatch;
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Secret = secret,
                    Platform = nameof(AssetPlatform.Dropbox),
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            const string NoAccessMessage = "Your app is not permitted to access this endpoint";
            const string DisabledMessage = "This app is currently disabled.";

            string secret = fingerprint.Secret;
            using HttpClient httpClient = CreateHttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secret);

            try
            {
                using HttpResponseMessage response = httpClient
                    .PostAsync("https://api.dropboxapi.com/2/file_requests/count", null)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return ValidationState.Authorized;
                    }

                    case HttpStatusCode.BadRequest:
                    {
                        string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                        // App deleted.
                        if (body.EndsWith(DisabledMessage))
                        {
                            return ValidationState.Expired;
                        }

                        // Request was successful but AccessToken does not have access.
                        if (body.Contains(NoAccessMessage))
                        {
                            if (secret.Length != 64)
                            {
                                // Short expiration token (4h).
                                resultLevelKind = new ResultLevelKind { Level = FailureLevel.Warning };
                            }

                            return ValidationState.Authorized;
                        }

                        // We don't recognize this message.
                        message = CreateUnexpectedResponseCodeMessage(response.StatusCode);
                        break;
                    }

                    case HttpStatusCode.Unauthorized:
                    {
                        return ValidationState.Unauthorized;
                    }

                    default:
                    {
                        message = CreateUnexpectedResponseCodeMessage(response.StatusCode);
                        break;
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e);
            }

            return ValidationState.Unknown;
        }
    }
}
