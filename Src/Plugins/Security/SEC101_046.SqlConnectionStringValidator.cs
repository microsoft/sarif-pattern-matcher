﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Data.SqlClient;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class SqlConnectionStringValidator : ValidatorBase
    {
        internal static SqlConnectionStringValidator Instance;
        internal static IRegex RegexEngine;

        private const string HostExpression = @"(?i)(Server|Data Source)\s*=\s*[^;""<]+";
        private const string DatabaseExpression = @"(?i)(Initial Catalog|Database)\s*=\s*[^;""<]+";
        private const string AccountExpression = @"(?i)(User ID|Uid)\s*=\s*[^;""<]+";
        private const string PasswordExpression = @"(?i)(Password|Pwd)\s*=\s*[^;""<\s]+";
        private const string ClientIPExpression = @"Client with IP address '[^']+' is not allowed to access the server.";

        private static readonly HashSet<string> HostsToExclude = new HashSet<string>
        {
            "postgres.database.azure.com",
            "mysql.database.azure.com",
        };

        static SqlConnectionStringValidator()
        {
            Instance = new SqlConnectionStringValidator();
            RegexEngine = RE2Regex.Instance;

            // We perform this work in order to force caching of these
            // expressions (an operation which otherwise can cause
            // threading problems).
            RegexEngine.Match(string.Empty, ClientIPExpression);
            RegexEngine.Match(string.Empty, HostExpression);
            RegexEngine.Match(string.Empty, DatabaseExpression);
            RegexEngine.Match(string.Empty, AccountExpression);
            RegexEngine.Match(string.Empty, PasswordExpression);
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
            matchedPattern = matchedPattern.Trim();

            string host, database, account, password;

            if (groups.ContainsKey("host") && groups.ContainsKey("database") && groups.ContainsKey("account") && groups.ContainsKey("password"))
            {
                host = groups["host"];
                account = groups["account"];
                database = groups["database"];
                password = groups["password"];
            }
            else
            {
                host = ParseExpression(RegexEngine, matchedPattern, HostExpression);
                account = ParseExpression(RegexEngine, matchedPattern, AccountExpression);
                database = ParseExpression(RegexEngine, matchedPattern, DatabaseExpression);
                password = ParseExpression(RegexEngine, matchedPattern, PasswordExpression);
            }

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

            if (database.Length > 128 ||
                account.Length > 128 ||
                password.Length > 128 ||
                host.Length > 128)
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint()
            {
                Host = host,
                Resource = database,
                Account = account,
                Password = password,
                Platform = SharedUtilities.GetDatabasePlatformFromHost(host, out _),
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message,
                                                       ref Dictionary<string, string> options)
        {
            var fingerprint = new Fingerprint(fingerprintText, false);

            string host = fingerprint.Host;
            string account = fingerprint.Account;
            string password = fingerprint.Password;
            string database = fingerprint.Resource;

            if (DomainFilteringHelper.LocalhostList.Contains(host))
            {
                return nameof(ValidationState.Unknown);
            }

            string connString =
                $"Server={host};Initial Catalog={database};User ID={account};Password={password};" +
                "Trusted_Connection=False;Encrypt=True;TrustServerCertificate=True;Connection Timeout=3;";
            message = $"the '{account}' account was authenticated against database '{database}' hosted on '{host}'";

            // Validating ConnectionString with database.
            string validation = ValidateConnectionString(ref message, host, connString, out bool shouldRetry);
            if (validation != nameof(ValidationState.Unknown) || !shouldRetry)
            {
                return validation;
            }

            connString =
               $"Server={host};User ID={account};Password={password};" +
               "Trusted_Connection=False;Encrypt=True;Connection Timeout=3;";
            message = $"the '{account}' account is compromised for server '{host}'";

            // Validating ConnectionString without database.
            return ValidateConnectionString(ref message, host, connString, out shouldRetry);
        }

        private static string ValidateConnectionString(ref string message, string host, string connString, out bool shouldRetry)
        {
            shouldRetry = true;

            try
            {
                using var connection = new SqlConnection(connString);
                connection.Open();
            }
            catch (ArgumentException)
            {
                // This exception means that some illegal chars, etc.
                // have snuck into the connection string
                return nameof(ValidationState.NoMatch);
            }
            catch (Exception e)
            {
                if (e is SqlException sqlException)
                {
                    if (sqlException.ErrorCode == unchecked((int)0x80131904))
                    {
                        if (e.Message.Contains("Login failed for user"))
                        {
                            return ReturnUnauthorizedAccess(ref message, asset: host);
                        }

                        FlexMatch match = RegexEngine.Match(e.Message, ClientIPExpression);
                        if (match.Success)
                        {
                            message = match.Value;
                            shouldRetry = false;
                            return nameof(ValidationState.Unknown);
                        }
                    }
                }

                return ReturnUnhandledException(ref message, e, asset: host);
            }

            return nameof(ValidationState.AuthorizedError);
        }
    }
}
