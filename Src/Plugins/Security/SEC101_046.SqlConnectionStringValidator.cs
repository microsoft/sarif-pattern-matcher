﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Data.SqlClient;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.HelpersUtiliesAndExtensions;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class SqlConnectionStringValidator : DomainFilteringValidator
    {
        internal static SqlConnectionStringValidator Instance;
        internal static IRegex RegexEngine;

        private const string HostExpression = @"(?i)(Server|Data Source)\s*=\s*[^;<]+";
        private const string DatabaseExpression = @"(?i)(Initial Catalog|Database)\s*=\s*[^;<]+";
        private const string AccountExpression = @"(?i)(User ID|Uid)\s*=\s*[^;<]+";
        private const string PasswordExpression = @"(?i)(Password|Pwd)\s*=\s*[^;<]+";
        private const string HostKey = "HOSTKEY";
        private const string DatabaseKey = "DATABASEKEY";
        private const string AccountKey = "ACCOUNTKEY";
        private const string PasswordKey = "PASSWORD";
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

        public static string IsValidDynamic(ref string fingerprint, ref string message)
        {
            return ValidatorBase.IsValidDynamic(Instance,
                                                ref fingerprint,
                                                ref message);
        }

        public override void MatchCleanup(ref string matchedPattern, ref Dictionary<string, string> groups, ref string failureLevel, ref string fingerprintText, ref string message)
        {
            matchedPattern = matchedPattern.Trim();

            string host, database, account, password;

            if (groups.ContainsKey("host") && groups.ContainsKey("database") && groups.ContainsKey("account") && groups.ContainsKey("password"))
            {
                host = groups["host"];
                database = groups["database"];
                account = groups["account"];
                password = groups["password"];
            }
            else
            {
                host = ParseExpression(RegexEngine, matchedPattern, HostExpression);
                database = ParseExpression(RegexEngine, matchedPattern, DatabaseExpression);
                account = ParseExpression(RegexEngine, matchedPattern, AccountExpression);
                password = ParseExpression(RegexEngine, matchedPattern, PasswordExpression);
            }

            groups.Add(HostKey, host);
            groups.Add(DatabaseKey, database);
            groups.Add(AccountKey, account);
            groups.Add(PasswordKey, password);

            StandardizeLocalhostName(groups, HostKey);
        }

        public override string HostExclusion(ref Dictionary<string, string> groups, IEnumerable<string> hostList = null, string hostKey = null)
        {
            return base.HostExclusion(ref groups, HostsToExclude, HostKey);
        }

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetNonEmptyValue(HostKey, out string host) ||
                !groups.TryGetNonEmptyValue(DatabaseKey, out string database) ||
                !groups.TryGetNonEmptyValue(AccountKey, out string account) ||
                !groups.TryGetNonEmptyValue(PasswordKey, out string password))
            {
                return nameof(ValidationState.NoMatch);
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
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            var fingerprint = new Fingerprint(fingerprintText);

            bool shouldRetry;
            string host = fingerprint.Host;
            string account = fingerprint.Account;
            string password = fingerprint.Password;
            string database = fingerprint.Resource;

            if (LocalhostList.Contains(host))
            {
                return nameof(ValidationState.Unknown);
            }

            string connString =
                $"Server={host};Initial Catalog={database};User ID={account};Password={password};" +
                "Trusted_Connection=False;Encrypt=True;Connection Timeout=30;";

            // Validating ConnectionString with database.
            string validation = ValidateConnectionString(ref message, host, connString, out shouldRetry);
            if (validation != nameof(ValidationState.Unknown) || !shouldRetry)
            {
                return validation;
            }

            connString =
               $"Server={host};User ID={account};Password={password};" +
               "Trusted_Connection=False;Encrypt=True;Connection Timeout=30;";

            // Validating ConnectionString without database.
            return ValidateConnectionString(ref message, host, connString, out shouldRetry);
        }

        private static string ValidateConnectionString(ref string message, string host, string connString, out bool shouldRetry)
        {
            shouldRetry = true;
            try
            {
                using var connection = new SqlConnection(connString);
                connection.OpenAsync().GetAwaiter().GetResult();
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

            return ReturnAuthorizedAccess(ref message, asset: host);
        }
    }
}
