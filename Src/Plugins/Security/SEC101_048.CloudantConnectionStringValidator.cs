// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.RE2.Managed;

using MySqlConnector;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Internal
{
    public class CloudantConnectionStringValidator : ValidatorBase
    {
        internal static CloudantConnectionStringValidator Instance;

        static CloudantConnectionStringValidator()
        {
            Instance = new CloudantConnectionStringValidator();
        }

        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return IsValidStatic(Instance,
                                ref matchedPattern,
                                ref groups,
                                ref failureLevel,
                                ref fingerprint,
                                ref message);
        }

        public static string IsValidDynamic(ref string fingerprint, ref string message)
        {
            return ValidatorBase.IsValidDynamic(Instance,
                                                ref fingerprint,
                                                ref message);
        }

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            // We need uri and neither account nor password, or uri and both account and password.  Use XOR
            if (!groups.TryGetNonEmptyValue("uri", out string uri) ||
                (groups.TryGetNonEmptyValue("account", out string account) ^
                groups.TryGetNonEmptyValue("password", out string password)))
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint()
            {
                Uri = uri,
                Account = account,
                Password = password,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            // TODO: Create a unit test for this. https://github.com/microsoft/sarif-pattern-matcher/issues/258

            var fingerprint = new Fingerprint(fingerprintText);
            string uri = fingerprint.Uri;
            string account = fingerprint.Account;
            string password = fingerprint.Password;

            try
            {
                // At this point account and password must be either both full or both empty.  Only check one
                if (string.IsNullOrWhiteSpace(account))
                {
                    using (HttpClient client = CreateHttpClient())
                    using (HttpResponseMessage response = client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult())
                    {
                        if (response.StatusCode == HttpStatusCode.OK)
                        {
                            return ReturnAuthorizedAccess(ref message, uri);
                        }

                        message = CreateUnexpectedResponseCodeMessage(response.StatusCode, uri);
                    }
                }
                else
                {
                    HttpClientHandler handler = new HttpClientHandler();
                    handler.Credentials = new NetworkCredential(account, password);
                    using (HttpClient client = new HttpClient(handler)
                    {
                        BaseAddress = new Uri(uri),
                    })
                    using (HttpResponseMessage response = client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult())
                    {
                        if (response.StatusCode == HttpStatusCode.OK)
                        {
                            return ReturnAuthorizedAccess(ref message, uri);
                        }

                        message = CreateUnexpectedResponseCodeMessage(response.StatusCode, uri);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: uri);
            }

            return nameof(ValidationState.Unknown);
        }
    }
}
