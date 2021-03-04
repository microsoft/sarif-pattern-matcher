// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.RE2.Managed;

using MySqlConnector;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Internal
{
    public class MySqlConnectionStringValidator : ValidatorBase
    {
        internal static MySqlConnectionStringValidator Instance;
        internal static IRegex RegexEngine;

        private const string HostRegex = "(?i)(Server\\s*=\\s*(?<host>[\\w\\-.]{3,90}))";
        private const string AccountRegex = "(?i)(Uid\\s*=\\s*(?-i)(?<account>[a-z\\@\\-]{1,120})(?i))";
        private const string PasswordRegex = "(?i)(Pwd\\s*=\\s*(?<password>[^;]{8,128}))";
        private const string DatabaseRegex = @"(?i)(Database\s*=\s*(?<database>[^\<>:""\/\\|?;.]{1,64}))";
        private const string PortRegex = "(?i)(Port\\s*=\\s*(?<port>[0-9]{4,5}))";

        private static readonly HashSet<string> HostsToExclude = new HashSet<string>
        {
            "database.windows.net",
            "postgres.database.azure.com",
        };

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
            string host = ParseExpression(RegexEngine, matchedPattern, HostRegex);
            string account = ParseExpression(RegexEngine, matchedPattern, AccountRegex);
            string password = ParseExpression(RegexEngine, matchedPattern, PasswordRegex);
            string database = ParseExpression(RegexEngine, matchedPattern, DatabaseRegex);
            string port = ParseExpression(RegexEngine, matchedPattern, PortRegex);

            if (string.IsNullOrWhiteSpace(host) ||
                string.IsNullOrWhiteSpace(database) ||
                string.IsNullOrWhiteSpace(account) ||
                string.IsNullOrWhiteSpace(password))
            {
                return nameof(ValidationState.NoMatch);
            }

            host = DomainFilteringHelper.StandardizeLocalhostName(host);

            string exclusionResult = DomainFilteringHelper.HostExclusion(host, HostsToExclude);

            if (exclusionResult == nameof(ValidationState.NoMatch))
            {
                return exclusionResult;
            }

            fingerprintText = new Fingerprint()
            {
                Host = host.Replace("\"", string.Empty).Replace(",", ";"),
                Resource = database,
                Port = port,
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
            string database = fingerprint.Resource;
            string port = fingerprint.Port;
            string account = fingerprint.Account;
            string password = fingerprint.Password;

            if (DomainFilteringHelper.LocalhostList.Contains(host))
            {
                return nameof(ValidationState.Unknown);
            }

            var connectionStringBuilder = new StringBuilder();
            connectionStringBuilder.Append($"Server={host}; Database={database}; Uid={account}; Pwd={password}; SslMode=Preferred;");
            message = $"the '{account}' account was authenticated against database '{database}' hosted on '{host}'";

            if (!string.IsNullOrWhiteSpace(port))
            {
                connectionStringBuilder.Append($"Port={port}");
            }

            try
            {
                using var conn = new MySqlConnection(connectionStringBuilder.ToString());
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

            return nameof(ValidationState.AuthorizedError);
        }
    }
}
