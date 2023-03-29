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
    public class SlackWebhookValidator : DynamicValidatorBase
    {
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
                    Platform = nameof(AssetPlatform.Slack),
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
            string asset = $"https://hooks.slack.com/services/{id}";
            string uri = $"{asset}/{secret}";

            HttpClient client = CreateOrRetrieveCachedHttpClient();

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, uri);
                if (options.TryGetValue("TestGuid", out string testingGuid))
                {
                    request.Content = new StringContent(testingGuid, Encoding.UTF8, "application/json");
                }
                else
                {
                    request.Content = new StringContent(ScanIdentityGuid, Encoding.UTF8, "application/json");
                }

                using HttpResponseMessage response = client
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                HttpStatusCode status = response.StatusCode;

                switch (status)
                {
                    case HttpStatusCode.BadRequest:
                    {
                        // We authenticated and our bogus payload was read.
                        return ValidationState.Authorized;
                    }

                    case HttpStatusCode.NotFound:
                    {
                        // The slack app itself could not be found.
                        message = "The specified Slack app could not be found.";
                        return ValidationState.UnknownHost;
                    }

                    case HttpStatusCode.Forbidden:
                    {
                        return ValidationState.Unauthorized;
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, status, account: id);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset);
            }
        }
    }
}
