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
        // Your database name can't end with '.' or ' ', can't contain '<,>,*,%,&,:,\,/,?' or control characters
        private const string ResourceExpression = @"(?i)(Initial Catalog|Database)\s*=\s*[^;""<>*%&:\/?\n]+";
        private const string IdExpression = @"(?i)(User ID|Uid)\s*=\s*[^;""'<\n]+";
        private const string SecretExpression = @"(?i)(Password|Pwd)\s*=\s*[^;""<\s]+";
        private const string ClientIPExpression = @"Client with IP address '[^']+' is not allowed to access the server.";

        private static readonly HashSet<string> HostsToExclude = new HashSet<string>
        {
            "postgres.database.azure.com",
            "mysql.database.azure.com",
            "mysqldb.chinacloudapi.cn",
            "mysql.database.chinacloudapi.cn",
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
            RegexEngine.Match(string.Empty, ResourceExpression);
            RegexEngine.Match(string.Empty, IdExpression);
            RegexEngine.Match(string.Empty, SecretExpression);
        }

        public static IEnumerable<ValidationResult> IsValidStatic(Dictionary<string, FlexMatch> groups)
        {
            return IsValidStatic(Instance, groups);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     Dictionary<string, string> options,
                                                     ref ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  options,
                                  ref resultLevelKind);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(Dictionary<string, FlexMatch> groups)
        {
            FlexMatch id, host, secret, database;

            id = host = secret = database = null;

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
                ParseExpression(RegexEngine, groups["0"], IdExpression, ref id);
                ParseExpression(RegexEngine, groups["0"], HostExpression, ref host);
                ParseExpression(RegexEngine, groups["0"], SecretExpression, ref secret);
                ParseExpression(RegexEngine, groups["0"], ResourceExpression, ref database);
            }

            if (string.IsNullOrWhiteSpace(id.Value) ||
                string.IsNullOrWhiteSpace(host.Value) ||
                string.IsNullOrWhiteSpace(secret.Value) ||
                string.IsNullOrWhiteSpace(database.Value))
            {
                return ValidationResult.CreateNoMatch();
            }

            string hostValue = FilteringHelpers.StandardizeLocalhostName(host.Value);

            ValidationState exclusionResult = FilteringHelpers.HostExclusion(hostValue, HostsToExclude);

            if (exclusionResult == ValidationState.NoMatch)
            {
                return ValidationResult.CreateNoMatch();
            }

            if (id.Length > 128 ||
                host.Length > 128 ||
                secret.Length > 128 ||
                database.Length > 128)
            {
                return ValidationResult.CreateNoMatch();
            }

            var fingerprint = new Fingerprint()
            {
                Id = id.Value,
                Host = hostValue,
                Secret = secret.Value,
                Resource = database.Value,
            };

            SharedUtilities.PopulateAssetFingerprint(hostValue, ref fingerprint);

            var validationResult = new ValidationResult
            {
                RegionFlexMatch = secret,
                Fingerprint = fingerprint,
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                Dictionary<string, string> options,
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

            string timeoutString = "Connection Timeout=3;";
            if (options.TryGetNonEmptyValue("retry", out string retry) && retry == bool.TrueString)
            {
                timeoutString = "Connection Timeout=15;";
            }

            string connString =
                $"Server={host};Initial Catalog={database};User ID={account};Password={password};" +
                $"Trusted_Connection=False;Encrypt=True;TrustServerCertificate=True;{timeoutString}";
            message = $"the '{account}' account was authenticated against database '{database}' hosted on '{host}'";

            // Validating ConnectionString with database.
            ValidationState validation = ValidateConnectionString(ref message, host, connString, out bool shouldRetry);
            if (validation != ValidationState.Unknown || !shouldRetry)
            {
                return validation;
            }

            connString =
               $"Server={host};User ID={account};Password={password};" +
               $"Trusted_Connection=False;Encrypt=True;{timeoutString}";
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
