// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Threading;

using Google.Apis.Auth.OAuth2;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GoogleServiceAccountKeyValidator : ValidatorBase
    {
        internal static GoogleServiceAccountKeyValidator Instance;

        static GoogleServiceAccountKeyValidator()
        {
            Instance = new GoogleServiceAccountKeyValidator();
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

        // TODO: Complete dynamic validation for Google client id and secret 
        // https://github.com/microsoft/sarif-pattern-matcher/issues/277
        //public static string IsValidDynamic(ref string fingerprint, ref string message)
        //{
        //    return IsValidDynamic(Instance,
        //                           ref fingerprint,
        //                           ref message);
        //}

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetNonEmptyValue("key", out string key))
            {
                return nameof(ValidationState.NoMatch);
            }

            // We might not succuessfully get account/client id
            groups.TryGetNonEmptyValue("account", out string account);

            fingerprintText = new Fingerprint()
            {
                Account = account,
                Key = key,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            var fingerprint = new Fingerprint(fingerprintText);
            string account = fingerprint.Account;
            string key = fingerprint.Key;

            if (string.IsNullOrWhiteSpace(account))
            {
                return nameof(ValidationState.Unknown);
            }

            try
            {
                ClientSecrets clientSecrets = new ClientSecrets()
                {
                    ClientId = account,
                    ClientSecret = key,
                };

                // This opens a browser.  Can we somehow get the information from the browser?
                // Or make our own calls, in-app instead?
                UserCredential credential = GoogleWebAuthorizationBroker.AuthorizeAsync(
                    clientSecrets,
                    new string[] { "Read" },
                    "user",
                    CancellationToken.None).Result;

                // ***** This throws no exception and allows dummy credentials to be added.
                // The result is a credentials object that is mostly empty. This means
                // verification is indeterminate.
                //var token = new TokenResponse { RefreshToken = null };
                //var credentials = new UserCredential(new GoogleAuthorizationCodeFlow(
                //    new GoogleAuthorizationCodeFlow.Initializer
                //    {
                //        ClientSecrets = clientSecrets,
                //    }),
                //    "user",
                //    token);

                //UserCredential testVar = credentials;
            }
            catch (Exception)
            { }

            return nameof(ValidationState.Unknown);
        }
    }
}
