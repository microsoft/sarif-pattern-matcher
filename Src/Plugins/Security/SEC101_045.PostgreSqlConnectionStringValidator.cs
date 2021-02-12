// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.HelpersUtiliesAndExtensions;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.HelpersUtilitiesAndExtensions;
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
        private const string PortKey = "PORTKEY";
        private const string DatabaseKey = "DATABASEKEY";

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
            if (!groups.TryGetNonEmptyValue("host", out string host) ||
                !groups.TryGetNonEmptyValue("account", out string account) ||
                !groups.TryGetNonEmptyValue("password", out string password))
            {
                return nameof(ValidationState.NoMatch);
            }

            string port = ParseExpression(RegexEngine, matchedPattern, PortRegex);
            string database = ParseExpression(RegexEngine, matchedPattern, DatabaseRegex);

            host = DomainFilteringHelper.StandardizeLocalhostName(host);

            string exclusionResult = DomainFilteringHelper.HostExclusion(ref host, HostsToExclude);

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
                                                       ref string message)
        {
            var fingerprint = new Fingerprint(fingerprintText);

            if (DomainFilteringHelper.LocalhostList.Contains(fingerprint.Host))
            {
                return nameof(ValidationState.Unknown);
            }

            var connectionStringBuilder = new StringBuilder();
            connectionStringBuilder.Append($"Host={fingerprint.Host};Username={fingerprint.Account};Password={fingerprint.Password};Ssl Mode=Require;");

            if (!string.IsNullOrWhiteSpace(fingerprint.Port))
            {
                connectionStringBuilder.Append($"Port={fingerprint.Port};");
            }

            if (!string.IsNullOrWhiteSpace(fingerprint.Resource))
            {
                connectionStringBuilder.Append($"Database={fingerprint.Resource};");
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
                        return ReturnAuthorizedAccess(ref message, asset: fingerprint.Host);
                    }

                    // password authentication failed for user
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
