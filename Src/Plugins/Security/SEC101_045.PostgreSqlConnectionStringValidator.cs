// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Npgsql;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class PostgreSqlConnectionStringValidator : ValidatorBase
    {
        internal static PostgreSqlConnectionStringValidator Instance;
        internal static IRegex RegexEngine;
        private const string PortRegex = @"(?i)Port\s*=\s*(?<port>[0-9]{1,5})";
        private const string DatabaseRegex = @"(?i)(database|db)\s*=\s*(?<database>[^;]+)";

        private static readonly HashSet<string> HostsToExclude = new HashSet<string>
        {
            "database.windows.net",
            "mysql.database.azure.com",
        };

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
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref failureLevel,
                                 ref fingerprint,
                                 ref message);
        }

        public static string IsValidDynamic(ref string fingerprint, ref string message, ref Dictionary<string, string> options)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options);
        }

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetNonEmptyValue("host", out string host) ||
                !groups.TryGetNonEmptyValue("account", out string account) ||
                !groups.TryGetNonEmptyValue("password", out string password))
            {
                return nameof(ValidationState.NoMatch);
            }

            if (host == "tcp")
            {
                return nameof(ValidationState.NoMatch);
            }

            string port = ParseExpression(RegexEngine, matchedPattern, PortRegex);
            string database = ParseExpression(RegexEngine, matchedPattern, DatabaseRegex);

            host = DomainFilteringHelper.StandardizeLocalhostName(host);

            string exclusionResult = DomainFilteringHelper.HostExclusion(host, HostsToExclude);

            if (exclusionResult == nameof(ValidationState.NoMatch))
            {
                return exclusionResult;
            }

            fingerprintText = new Fingerprint()
            {
                Host = host,
                Port = port,
                Resource = database,
                Account = account,
                Password = password,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message,
                                                       ref Dictionary<string, string> options)
        {
            var fingerprint = new Fingerprint(fingerprintText, false);
            string host = fingerprint.Host;
            string port = fingerprint.Port;
            string account = fingerprint.Account;
            string password = fingerprint.Password;
            string database = fingerprint.Resource;

            if (DomainFilteringHelper.LocalhostList.Contains(host))
            {
                return nameof(ValidationState.Unknown);
            }

            var connectionStringBuilder = new StringBuilder();
            message = $"the '{account}' account is compromised for server '{host}'";
            connectionStringBuilder.Append($"Host={host};Username={account};Password={password};Ssl Mode=Require;");

            if (!string.IsNullOrWhiteSpace(port))
            {
                connectionStringBuilder.Append($"Port={port};");
            }

            if (!string.IsNullOrWhiteSpace(database))
            {
                message = $"the '{account}' account was authenticated against database '{database}' hosted on '{host}'";
                connectionStringBuilder.Append($"Database={database};");
            }

            try
            {
                using var postgreSqlconnection = new NpgsqlConnection(connectionStringBuilder.ToString());
                postgreSqlconnection.Open();
            }
            catch (Exception e)
            {
                if (e is PostgresException postgresException)
                {
                    // Database does not exist, but the creds are valid
                    if (postgresException.SqlState == "3D000")
                    {
                        return ReturnAuthorizedAccess(ref message, asset: host);
                    }

                    // password authentication failed for user
                    if (postgresException.SqlState == "28P01")
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: host);
                    }
                }

                return ReturnUnhandledException(ref message, e.InnerException ?? e, asset: host);
            }

            return nameof(ValidationState.AuthorizedError);
        }
    }
}
