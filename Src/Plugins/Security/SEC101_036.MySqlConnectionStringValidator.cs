// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using MySqlConnector;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class MySqlConnectionStringValidator : ValidatorBase
    {
        internal static MySqlConnectionStringValidator Instance;
        internal static IRegex RegexEngine;

        private const string DatabaseRegex = @"(?i)(Database\s*=\s*(?<database>[^\<>:""\/\\|?;.]{1,64}))";
        private const string PortRegex = "(?i)(Port\\s*=\\s*(?<port>[0-9]{4,5}))";

        private static readonly HashSet<string> HostsToExclude = new HashSet<string>
        {
            "database.windows.net",
            "database.chinacloudapi.cn", // Azure China domain
            "postgres.database.azure.com",
        };

        static MySqlConnectionStringValidator()
        {
            Instance = new MySqlConnectionStringValidator();
            RegexEngine = RE2Regex.Instance;
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

            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationState.NoMatch;
            }

            // Our matches can sometimes fail to find a host (due to it being constructed in code)
            // However, the credentials can still be valid, so we should return "unknown".
            // Grab the empty host here and then short circuit in dynamic validation.

            fingerprint = new Fingerprint()
            {
                Id = id,
                Secret = secret,
            };

            if (!groups.TryGetNonEmptyValue("host", out string host))
            {
                return ValidationState.Unknown;
            }

            if (host == "tcp")
            {
                return ValidationState.NoMatch;
            }

            string database = ParseExpression(RegexEngine, matchedPattern, DatabaseRegex);
            string port = ParseExpression(RegexEngine, matchedPattern, PortRegex);

            host = FilteringHelpers.StandardizeLocalhostName(host);

            ValidationState exclusionResult = FilteringHelpers.HostExclusion(host, HostsToExclude);

            if (exclusionResult == ValidationState.NoMatch)
            {
                return exclusionResult;
            }

            fingerprint.Port = port;
            fingerprint.Host = host.Replace("\"", string.Empty).Replace(",", ";");
            fingerprint.Resource = database;

            SharedUtilities.PopulateAssetFingerprint(host, ref fingerprint);

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string host = fingerprint.Host;
            string port = fingerprint.Port;
            string account = fingerprint.Id;
            string password = fingerprint.Secret;
            string database = fingerprint.Resource;

            if (string.IsNullOrWhiteSpace(host) ||
                string.IsNullOrWhiteSpace(database) ||
                FilteringHelpers.LocalhostList.Contains(host))
            {
                return ValidationState.Unknown;
            }

            string connString = $"Server={host}; Database={database}; Uid={account}; Pwd={password}; SslMode=Preferred;";
            message = $"the '{account}' account was authenticated against database '{database}' hosted on '{host}'";

            if (!string.IsNullOrWhiteSpace(port))
            {
                connString += $"Port={port}";
            }

            // Validating ConnectionString with database.
            ValidationState validationState = ValidateConnectionString(ref message, host, connString, out bool shouldRetry);
            if (validationState != ValidationState.Unknown || !shouldRetry)
            {
                return validationState;
            }

            connString = $"Server={host}; Uid={account}; Pwd={password}; SslMode=Preferred;";
            message = $"the '{account}' account is compromised for server '{host}'";

            if (!string.IsNullOrWhiteSpace(port))
            {
                connString += $"Port={port}";
            }

            // Validating ConnectionString without database.
            return ValidateConnectionString(ref message, host, connString, out shouldRetry);
        }

        private static ValidationState ValidateConnectionString(ref string message, string host, string connString, out bool shouldRetry)
        {
            shouldRetry = true;

            try
            {
                using var connection = new MySqlConnection(connString);
                connection.Open();
            }
            catch (Exception e)
            {
                if (e is MySqlException mysqlException)
                {
                    // ErrorCode = 9000: Client with IP address is not allowed to connect to this MySQL server.
                    if (mysqlException.ErrorCode == (MySqlErrorCode)9000 ||
                        mysqlException.ErrorCode == MySqlErrorCode.AccessDenied)
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: host);
                    }

                    if (mysqlException.ErrorCode == MySqlErrorCode.UnableToConnectToHost)
                    {
                        return ReturnUnknownHost(ref message, host);
                    }
                }

                return ReturnUnhandledException(ref message, e, asset: host);
            }

            return ValidationState.Authorized;
        }
    }
}
