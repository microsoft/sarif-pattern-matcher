// Copyright (c) Microsoft. All rights reserved.
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

        private const string HostExpression = @"(?i)(Server|Data Source)\s*=\s*[^;""<\n]+";
        private const string DatabaseExpression = @"(?i)(Initial Catalog|Database)\s*=\s*[^;""<>*%&:\/?\n]+"; // Your database name can't end with '.' or ' ', can't contain '<,>,*,%,&,:,\,/,?' or control characters
        private const string AccountExpression = @"(?i)(User ID|Uid)\s*=\s*[^;""'<\n]+";
        private const string PasswordExpression = @"(?i)(Password|Pwd)\s*=\s*[^;""<\s]+";
        private const string ClientIPExpression = @"Client with IP address '[^']+' is not allowed to access the server.";

        private static readonly HashSet<string> HostsToExclude = new HashSet<string>
        {
            "postgres.database.azure.com",
            "mysql.database.azure.com",
            "mysqldb.chinacloudapi.cn", // Azure China domain
            "mysql.database.chinacloudapi.cn", // Azure China domain
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

        public static ValidationState IsValidStatic(ref string matchedPattern,
                                                    ref Dictionary<string, string> groups,
                                                    ref string message,
                                                    out ResultLevelKind resultLevelKind,
                                                    out Fingerprint fingerprint)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref message,
                                 out resultLevelKind,
                                 out fingerprint);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     ref Dictionary<string, string> options,
                                                     ref ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options,
                                  ref resultLevelKind);
        }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                               ref Dictionary<string, string> groups,
                                                               ref string message,
                                                               out ResultLevelKind resultLevelKind,
                                                               out Fingerprint fingerprint)
        {
            fingerprint = default;
            resultLevelKind = default;
            matchedPattern = matchedPattern.Trim();

            string id, host, secret, database;

            if (groups.ContainsKey("id") &&
                groups.ContainsKey("host") &&
                groups.ContainsKey("secret") &&
                groups.ContainsKey("database"))
            {
                id = groups["id"];
                host = groups["host"];
                secret = groups["secret"];
                database = groups["database"];
            }
            else
            {
                id = ParseExpression(RegexEngine, matchedPattern, AccountExpression);
                host = ParseExpression(RegexEngine, matchedPattern, HostExpression);
                secret = ParseExpression(RegexEngine, matchedPattern, PasswordExpression);
                database = ParseExpression(RegexEngine, matchedPattern, DatabaseExpression);
            }

            if (string.IsNullOrWhiteSpace(id) ||
                string.IsNullOrWhiteSpace(host) ||
                string.IsNullOrWhiteSpace(secret) ||
                string.IsNullOrWhiteSpace(database))
            {
                return ValidationState.NoMatch;
            }

            host = FilteringHelpers.StandardizeLocalhostName(host);

            ValidationState exclusionResult = FilteringHelpers.HostExclusion(host, HostsToExclude);

            if (exclusionResult == ValidationState.NoMatch)
            {
                return exclusionResult;
            }

            if (id.Length > 128 ||
                host.Length > 128 ||
                secret.Length > 128 ||
                database.Length > 128)
            {
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint()
            {
                Id = id,
                Host = host,
                Secret = secret,
                Resource = database,
            };

            SharedUtilities.PopulateAssetFingerprint(host, ref fingerprint);

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string host = fingerprint.Host;
            string account = fingerprint.Id;
            string password = fingerprint.Secret;
            string database = fingerprint.Resource;

            if (FilteringHelpers.LocalhostList.Contains(host))
            {
                return ValidationState.Unknown;
            }

            string connString =
                $"Server={host};Initial Catalog={database};User ID={account};Password={password};" +
                "Trusted_Connection=False;Encrypt=True;TrustServerCertificate=True;Connection Timeout=3;";
            message = $"the '{account}' account was authenticated against database '{database}' hosted on '{host}'";

            // Validating ConnectionString with database.
            ValidationState validation = ValidateConnectionString(ref message, host, connString, out bool shouldRetry);
            if (validation != ValidationState.Unknown || !shouldRetry)
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

        private static ValidationState ValidateConnectionString(ref string message, string host, string connString, out bool shouldRetry)
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
                return ValidationState.NoMatch;
            }
            catch (Exception e)
            {
                if (e is SqlException sqlException)
                {
                    if (sqlException.ErrorCode == unchecked((int)0x80131904))
                    {
                        if (e.Message.Contains("Login failed for user") ||
                            e.Message.EndsWith("The login failed."))
                        {
                            return ReturnUnauthorizedAccess(ref message, asset: host);
                        }

                        FlexMatch match = RegexEngine.Match(e.Message, ClientIPExpression);
                        if (match.Success)
                        {
                            message = match.Value;
                            shouldRetry = false;
                            return ValidationState.Unknown;
                        }
                    }
                }

                return ReturnUnhandledException(ref message, e, asset: host);
            }

            return ValidationState.Authorized;
        }
    }
}
