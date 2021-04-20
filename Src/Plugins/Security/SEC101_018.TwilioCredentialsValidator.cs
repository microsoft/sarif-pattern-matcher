// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class TwilioCredentialsValidator : ValidatorBase
    {
        internal static TwilioCredentialsValidator Instance;

        static TwilioCredentialsValidator()
        {
            Instance = new TwilioCredentialsValidator();
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
            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationResult.NoMatch;
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Id = id,
                    Secret = secret,
                    Platform = nameof(AssetPlatform.Twilio),
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
            string id = fingerprint.Id;
            string secret = fingerprint.Secret;

            try
            {
                string credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", id, secret)));
                using HttpClient httpClient = CreateHttpClient();
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

                using HttpResponseMessage response = httpClient
                    .GetAsync($"https://api.twilio.com/2010-04-01/Accounts.json", HttpCompletionOption.ResponseHeadersRead)
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

                    default:
                    {
                        message = CreateUnexpectedResponseCodeMessage(response.StatusCode);
                        return ValidationState.Unknown;
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
