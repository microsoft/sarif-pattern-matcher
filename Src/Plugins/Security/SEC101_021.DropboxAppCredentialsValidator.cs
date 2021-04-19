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
    public class DropboxAppCredentialsValidator : ValidatorBase
    {
        internal static DropboxAppCredentialsValidator Instance;

        static DropboxAppCredentialsValidator()
        {
            Instance = new DropboxAppCredentialsValidator();
        }

        public static ValidationState IsValidStatic(ref string matchedPattern,
                                                    ref Dictionary<string, string> groups,
                                                    ref string message,
                                                    out ResultLevelKind resultLevelKind,
                                                    out Fingerprint fingerprint)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref message,
                                 out resultLevelKind,
                                 out fingerprint);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     ref Dictionary<string, string> options,
                                                     out ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options,
                                  out resultLevelKind);
        }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                               ref Dictionary<string, string> groups,
                                                               ref string message,
                                                               out ResultLevelKind resultLevelKind,
                                                               out Fingerprint fingerprint)
        {
            fingerprint = default;
            resultLevelKind = default;

            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationState.NoMatch;
            }

            if (!ContainsDigitAndChar(id) ||
                !ContainsDigitAndChar(secret))
            {
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint()
            {
                Id = id,
                Secret = secret,
                Platform = nameof(AssetPlatform.Dropbox),
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                 ref string message,
                                                                 ref Dictionary<string, string> options,
                                                                 out ResultLevelKind resultLevelKind)
        {
            resultLevelKind = new ResultLevelKind
            {
                Level = FailureLevel.Note,
            };

            string id = fingerprint.Id;
            string secret = fingerprint.Secret;
            string credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", id, secret)));
            using HttpClient httpClient = CreateHttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);
            httpClient.DefaultRequestHeaders.Add("Dropbox-API-Arg", @"{""resource"": {"".tag"": ""path"",""path"": ""/a.docx""},""format"": ""jpeg"",""size"": ""w64h64"",""mode"": ""strict""}");

            try
            {
                using HttpResponseMessage response = httpClient
                    .PostAsync("https://content.dropboxapi.com/2/files/get_thumbnail_v2", null)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.InternalServerError:
                    {
                        resultLevelKind.Level = FailureLevel.Error;

                        // The request is correct, but the header 'Dropbox-API-Arg' is wrong.
                        return ValidationState.AuthorizedError;
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

                        // We don't recognize this message.
                        message = CreateUnexpectedResponseCodeMessage(response.StatusCode);
                        return ValidationState.Unknown;
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
