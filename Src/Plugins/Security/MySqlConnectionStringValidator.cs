// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.RE2.Managed;
using MySqlConnector;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Internal
{
    internal class MySqlConnectionStringValidator : ValidatorBase
    {
        internal static MySqlConnectionStringValidator Instance;
        internal static IRegex RegexEngine;

        static MySqlConnectionStringValidator()
        {
            Instance = new MySqlConnectionStringValidator();
            RegexEngine = RE2Regex.Instance;
        }

        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return ValidatorBase.IsValidStatic(Instance,
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
            if (!groups.TryGetValue("host", out string host) ||
                !groups.TryGetValue("account", out string account) ||
                !groups.TryGetValue("password", out string password))
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint()
            {
                Host = host.Replace("\"", string.Empty).Replace(",", ";"),
                Account = account,
                Password = password,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            var fingerprint = new Fingerprint(fingerprintText);

            string host = fingerprint.Host;
            string account = fingerprint.Account;
            string password = fingerprint.Password;

            string connString = $"Server={host}; Uid={account}; Pwd={password}; SslMode=Preferred;";
            try
            {
                using var conn = new MySqlConnection(connString);
                conn.Open();
            }
            catch (Exception e)
            {
                if (e is MySqlException mysqlException)
                {
                    if (mysqlException.ErrorCode == MySqlErrorCode.AccessDenied)
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: host);
                    }
                }

                return ReturnUnhandledException(ref message, e, asset: host);
            }

            return ReturnAuthorizedAccess(ref message, asset: host);
        }
    }
}
