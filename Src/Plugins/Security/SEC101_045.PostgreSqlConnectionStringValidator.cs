// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.RE2.Managed;

using Npgsql;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class PostgreSqlConnectionStringValidator : ValidatorBase
    {
        internal static PostgreSqlConnectionStringValidator Instance;
        internal static IRegex RegexEngine;
        private const string HostRegex = @"(?i)(host|server)\s*=\s*(?-i)(?<host>[\w\-_\.]{3,91})";
        private const string PortRegex = @"(?i)Port\s*=\s*(?<port>[0-9]{1,5})";
        private const string AccountRegex = @"(?i)(username|uid|user id)\s*=\s*(?<account>[^,;]+)";
        private const string PasswordRegex = @"(?i)(password|pwd)\s*=\s*(?<password>[^,;""\s]+)";
        private const string DatabaseRegex = @"(?i)(database|db)\s*=\s*(?<database>[^;]+)";

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
            string host = ParseExpression(RegexEngine, matchedPattern, HostRegex);
            string port = ParseExpression(RegexEngine, matchedPattern, PortRegex);
            string account = ParseExpression(RegexEngine, matchedPattern, AccountRegex);
            string password = ParseExpression(RegexEngine, matchedPattern, PasswordRegex);
            string database = ParseExpression(RegexEngine, matchedPattern, DatabaseRegex);

            if (string.IsNullOrWhiteSpace(host) ||
                string.IsNullOrWhiteSpace(account) ||
                string.IsNullOrWhiteSpace(password))
            {
                return nameof(ValidationState.NoMatch);
            }

            if (LocalhostList.Contains(host))
            {
                host = "localhost";
            }

            // Other rules will handle these cases.
            if (host.EndsWith("database.windows.net", StringComparison.OrdinalIgnoreCase) ||
                host.EndsWith("mysql.database.azure.com", StringComparison.OrdinalIgnoreCase))
            {
                return nameof(ValidationState.NoMatch);
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

            if (LocalhostList.Contains(fingerprint.Host))
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
