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
    public class DropboxAppCredentialsValidator : DynamicValidatorBase
    {
        internal const string Uri = "https://content.dropboxapi.com/2/files/get_thumbnail_v2";

        internal static HttpRequestMessage GenerateRequestMessage(string id, string secret)
        {
            string credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", id, secret)));
            var request = new HttpRequestMessage(HttpMethod.Post, Uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            request.Headers.Add("Dropbox-API-Arg", @"{""resource"": {"".tag"": ""path"",""path"": ""/a.docx""},""format"": ""jpeg"",""size"": ""w64h64"",""mode"": ""strict""}");
            return request;
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch id = groups["id"];
            FlexMatch secret = groups["secret"];

            if (!id.Value.ToString().ContainsDigitAndLetter() ||
                !secret.Value.ToString().ContainsDigitAndLetter())
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Id = id.Value,
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.Dropbox),
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
            HttpClient httpClient = CreateOrRetrieveCachedHttpClient();

            try
            {
                using var request = GenerateRequestMessage(id, secret);
                using HttpResponseMessage response = httpClient
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.InternalServerError:
                    {
                        // The request is correct, but the header 'Dropbox-API-Arg' is wrong.
                        return ValidationState.Authorized;
                    }

                    case HttpStatusCode.BadRequest:
                    {
                        string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                        // App deleted.
                        if (body.Contains("App has been disabled"))
                        {
                            return ValidationState.Expired;
                        }

                        if (body.Contains("invalid_client"))
                        {
                            return ValidationState.Unauthorized;
                        }

                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode, account: id);
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode, account: id);
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
