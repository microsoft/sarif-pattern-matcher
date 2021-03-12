// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Security;

using GoogleApi.Entities.Maps.Elevation.Response;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.Identity.Client;

using Org.BouncyCastle.Asn1.X509.Qualified;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class UserPasswordCredentialValidator : ValidatorBase
    {
        private const string UnknownUserType = "unknown_user_type";
        private const string ParsingWSTrustResponseFailed = "parsing_wstrust_response_failed";
        private const string UnauthorizedClient = "unauthorized_client";

        internal static UserPasswordCredentialValidator Instance;

        static UserPasswordCredentialValidator()
        {
            Instance = new UserPasswordCredentialValidator();
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
            return IsValidDynamic(Instance,
                                   ref fingerprint,
                                   ref message);
        }

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetNonEmptyValue("password", out string password) ||
                !groups.TryGetNonEmptyValue("account", out string account))
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint()
            {
                Account = account,
                Password = password,
            }.ToString();

            return nameof(ValidationState.AuthorizedWarning);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            var fingerprint = new Fingerprint(fingerprintText);
            string account = fingerprint.Account;
            string password = fingerprint.Password;

            string authority = "https://login.microsoftonline.com/contoso.com";
            string[] scopes = new string[] { "user.read" };
            var securePassword = new SecureString();
            string clientId = "test";

            // MSAL requires that we enter the password one character at a time
            foreach (char c in password)
            {
                securePassword.AppendChar(c);
            }

            IPublicClientApplication app;
            app = PublicClientApplicationBuilder.Create(clientId)
                  .WithAuthority(authority)
                  .Build();

            AuthenticationResult result = null;
            try
            {
                result = app.AcquireTokenByUsernamePassword(scopes,
                                                            account,
                                                            securePassword).ExecuteAsync().Result;
            }
            catch (AggregateException ae)
            {
                var clientException = ae.InnerExceptions[0] as MsalClientException;
                if (clientException != null)
                {
                    switch (clientException.ErrorCode)
                    {
                        case UnknownUserType:
                            // Username probably missing @microsoft.com or something similar
                        case ParsingWSTrustResponseFailed:
                            // One or both of username and password is wrong
                            return ReturnUnauthorizedAccess(ref message, asset: account);
                        default:
                            break;
                    }
                }

                var serviceException = ae.InnerExceptions[0] as MsalServiceException;
                if (serviceException != null)
                {
                    if (serviceException.ErrorCode == UnauthorizedClient)
                    {
                        // Username right, password right, dummy client id
                        return ReturnAuthorizedAccess(ref message, asset: account);
                    }
                }

                return ReturnUnhandledException(ref message, ae);
            }

            // Should be unreachable if all goes as expected
            message = $"Unexpected MSAL behavior, the access token was {(string.IsNullOrWhiteSpace(result?.AccessToken) ? string.Empty : "not ")}empty";
            return nameof(ValidationState.Unknown);
        }
    }
}
