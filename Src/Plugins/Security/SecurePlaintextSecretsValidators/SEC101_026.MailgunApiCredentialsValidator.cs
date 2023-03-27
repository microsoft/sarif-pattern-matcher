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
    public class MailgunApiCredentialsValidator : DynamicValidatorBase
    {
        internal static HttpRequestMessage GenerateRequestMessage(string id, string secret, string scanIdentityGuid)
        {
            string credentials = $"api:{secret}";
            byte[] bytes = Encoding.UTF8.GetBytes(credentials);
            credentials = Convert.ToBase64String(bytes);

            var request = new HttpRequestMessage(HttpMethod.Post, $"https://api.mailgun.net/v3/{id}.mailgun.org/messages");
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            request.Content = new MultipartFormDataContent
            {
                { new StringContent(scanIdentityGuid), "subject" },
            };
            return request;
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch id = groups["id"];
            FlexMatch secret = groups["secret"];

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Id = id.Value,
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.Mailgun),
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

            try
            {
                HttpClient client = CreateOrRetrieveCachedHttpClient();

                using var request = GenerateRequestMessage(id, secret, ScanIdentityGuid);

                using HttpResponseMessage response = client
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
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
                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode, account: id);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: id);
            }
        }
    }
}
