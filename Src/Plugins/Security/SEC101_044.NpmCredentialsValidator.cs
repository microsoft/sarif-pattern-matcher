// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class NpmCredentialsValidator : ValidatorBase
    {
        internal static NpmCredentialsValidator Instance;

        static NpmCredentialsValidator()
        {
            Instance = new NpmCredentialsValidator();
        }

        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  Dictionary<string, string> groups)
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
                                                                             Dictionary<string, string> groups)
        {
            if (!groups.TryGetNonEmptyValue("host", out string host) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            if (!ContainsDigitAndChar(secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            groups.TryGetValue("id", out string id);

            try
            {
                byte[] data = Convert.FromBase64String(secret);
                string decodedString = Encoding.UTF8.GetString(data);

                if (decodedString.Contains(':'))
                {
                    string[] parts = decodedString.Split(':');
                    id = parts[0];
                    secret = parts[1];
                }
                else
                {
                    secret = decodedString;
                }
            }
            catch (FormatException)
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Id = id,
                    Host = host,
                    Secret = secret,
                    Platform = nameof(AssetPlatform.NuGet),
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
            string host = fingerprint.Host;
            string secret = fingerprint.Secret;
            string uri = $"https://{host}";

            using HttpClient client = CreateHttpClient();

            try
            {
                using HttpResponseMessage responseWithNoCredentials = client
                    .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                if (responseWithNoCredentials.StatusCode == HttpStatusCode.OK ||
                    responseWithNoCredentials.StatusCode == HttpStatusCode.NotFound ||
                    responseWithNoCredentials.StatusCode == HttpStatusCode.NonAuthoritativeInformation)
                {
                    return ValidationState.NoMatch;
                }

                string credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", id, secret)));
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);
                using HttpResponseMessage responseWithCredentials = client
                    .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (responseWithCredentials.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return ReturnAuthorizedAccess(ref message, host, account: id);
                    }

                    case HttpStatusCode.Unauthorized:
                    {
                        return ReturnUnauthorizedAccess(ref message, host, account: id);
                    }

                    default:
                    {
                        message = CreateUnexpectedResponseCodeMessage(responseWithCredentials.StatusCode, host);
                        return ValidationState.Unknown;
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: host, account: id);
            }
        }
    }
}
