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
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class DropboxAppCredentialsValidator : ValidatorBase
    {
        internal static DropboxAppCredentialsValidator Instance;

        static DropboxAppCredentialsValidator()
        {
            Instance = new DropboxAppCredentialsValidator();
        }

        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  Dictionary<string, FlexMatch> groups)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 groups);
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

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(ref string matchedPattern,
                                                                             Dictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            if (!ContainsDigitAndChar(id.Value) ||
                !ContainsDigitAndChar(secret.Value))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                RegionFlexMatch = secret,
                Fingerprint = new Fingerprint()
                {
                    Id = id.Value,
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.Dropbox),
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
