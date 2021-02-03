// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.RE2.Managed;

using Npgsql;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class PostgreSqlConnectionStringValidator : ValidatorBase
    {
        internal static PostgreSqlConnectionStringValidator Instance;
        internal static IRegex RegexEngine;
        private const string _hostRegex = "(?i)(Host\\s*=\\s*(?-i)(?<host>[\\w\\-_\\.]{3,91}))";
        private const string _portRegex = "(?i)(Port\\s*=\\s*(?<port>[0-9]{1,5}))";
        private const string _accountRegex = "(?i)(Username\\s*=\\s*(?<account>[^,;]+))";
        private const string _passwordRegex = "(?i)(Password\\s*=\\s*(?<account>[^,;\"\\s]+))";

        static PostgreSqlConnectionStringValidator()
        {
            Instance = new PostgreSqlConnectionStringValidator();
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
            GetStringFromPatternWithRegex(matchedPattern, _hostRegex, out string host);
            GetStringFromPatternWithRegex(matchedPattern, _portRegex, out string port);
            GetStringFromPatternWithRegex(matchedPattern, _accountRegex, out string account);
            GetStringFromPatternWithRegex(matchedPattern, _passwordRegex, out string password);

            if (string.IsNullOrWhiteSpace(host) ||
                string.IsNullOrWhiteSpace(account) ||
                string.IsNullOrWhiteSpace(password))
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint()
            {
                Host = host,
                Port = port,
                Account = account,
                Password = password,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        private static void GetStringFromPatternWithRegex(string matchedPattern, string regex, out string stringFromPattern)
        {
            FlexMatch flexMatch = RegexEngine.Match(matchedPattern, regex);

            if (flexMatch == null || !flexMatch.Success)
            {
                stringFromPattern = null;
                return;
            }

            // The regular expressions defined in constants above will capture entire properties.
            // For example:  "Password=blahblah" would be an entire match.
            // We only need that which follows the first equal sign (just in case there are many)

            int indexOfFirstEqualSign = flexMatch.Value.String.IndexOf('=');

            // If we didn't find an equal sign or the equal sign is the last character (the property is empty) return null
            if (indexOfFirstEqualSign < 0 || indexOfFirstEqualSign == flexMatch.Value.String.Length - 1)
            {
                stringFromPattern = null;
                return;
            }

            stringFromPattern = flexMatch.Value.String.Substring(indexOfFirstEqualSign + 1);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            var fingerprint = new Fingerprint(fingerprintText);

            string connString;
            if (string.IsNullOrWhiteSpace(fingerprint.Port))
            {
                connString = $"Host={fingerprint.Host};Username={fingerprint.Account};Password={fingerprint.Password};Ssl Mode=Require";
            }
            else
            {
                connString = $"Host={fingerprint.Host};Port={fingerprint.Port};Username={fingerprint.Account};Password={fingerprint.Password};Ssl Mode=Require";
            }

            try
            {
                using var postgreSqlconnection = new NpgsqlConnection(connString);
                postgreSqlconnection.Open();
            }
            catch (Exception e)
            {
                if (e is PostgresException postgresException)
                {
                    // database does not exist, but the creds are valid
                    if (postgresException.SqlState == "3D000")
                    {
                        return ReturnAuthorizedAccess(ref message, asset: fingerprint.Host);
                    }

                    // password authentication failed for user "sectoojlsadm"
                    if (postgresException.SqlState == "28P01")
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: fingerprint.Host);
                    }
                }

                return ReturnUnhandledException(ref message, e, asset: fingerprint.Host);
            }

            return ReturnAuthorizedAccess(ref message, asset: fingerprint.Host);
        }
    }
}
