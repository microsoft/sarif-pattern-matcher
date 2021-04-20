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
    public class MailgunApiCredentialsValidator : ValidatorBase
    {
        internal static MailgunApiCredentialsValidator Instance = new MailgunApiCredentialsValidator();

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
                    Platform = nameof(AssetPlatform.Mailgun),
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
                using HttpClient client = CreateHttpClient();

                string credentials = $"api:{secret}";
                byte[] bytes = Encoding.UTF8.GetBytes(credentials);
                credentials = Convert.ToBase64String(bytes);

                client.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Basic", credentials);

                var content = new MultipartFormDataContent();
                content.Add(new StringContent(Guid.NewGuid().ToString()), "subject");

                using HttpResponseMessage response = client
                    .PostAsync($"https://api.mailgun.net/v3/{id}/messages", content)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.BadRequest:
                    {
                        return ReturnAuthorizedAccess(ref message, asset: id);
                    }

                    case HttpStatusCode.Unauthorized:
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: id);
                    }

                    default:
                    {
                        message = $"An unexpected response code was returned attempting to " +
                                  $"validate the '{id}' account: '{response.StatusCode}'";
                        break;
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: id);
            }

            return ValidationState.Unknown;
        }
    }
}
