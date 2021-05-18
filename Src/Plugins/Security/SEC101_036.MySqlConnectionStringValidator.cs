// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

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

        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  Dictionary<string, FlexMatch> groups)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 groups);
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

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(ref string matchedPattern,
                                                                             Dictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            // Our matches can sometimes fail to find a host (due to it being constructed in code)
            // However, the credentials can still be valid, so we should return "unknown".
            // Grab the empty host here and then short circuit in dynamic validation.

            var fingerprint = new Fingerprint()
            {
                Id = id.Value,
                Secret = secret.Value,
            };
            var validationResult = new ValidationResult();

            if (!groups.TryGetNonEmptyValue("host", out FlexMatch host))
            {
                validationResult.Fingerprint = fingerprint;
                validationResult.ValidationState = ValidationState.Unknown;
                return new[] { validationResult };
            }

            if (host.Value == "tcp")
            {
                return ValidationResult.CreateNoMatch();
            }

            FlexMatch unused = null;
            string database = ParseExpression(RegexEngine, matchedPattern, DatabaseRegex, ref unused);
            string port = ParseExpression(RegexEngine, matchedPattern, PortRegex, ref unused);

            string hostValue = FilteringHelpers.StandardizeLocalhostName(host.Value);

            ValidationState exclusionResult = FilteringHelpers.HostExclusion(hostValue, HostsToExclude);

            if (exclusionResult == ValidationState.NoMatch)
            {
                return ValidationResult.CreateNoMatch();
            }

            fingerprint.Port = port;
            fingerprint.Host = hostValue.Replace("\"", string.Empty).Replace(",", ";");
            fingerprint.Resource = database;

            SharedUtilities.PopulateAssetFingerprint(hostValue, ref fingerprint);
            validationResult.RegionFlexMatch = secret;
            validationResult.Fingerprint = fingerprint;
            validationResult.ValidationState = ValidationState.Unknown;

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                Dictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string host = fingerprint.Host;
            string port = fingerprint.Port;
            string account = fingerprint.Id;
            string password = fingerprint.Secret;
            string database = fingerprint.Resource;

            if (string.IsNullOrWhiteSpace(host) ||
                FilteringHelpers.LocalhostList.Contains(host))
            {
                return ValidationState.Unknown;
            }

            bool shouldRetry;
            string connString;
            if (!string.IsNullOrWhiteSpace(database))
            {
                connString = $"Server={host}; Database={database}; Uid={account}; Pwd={password}; SslMode=Preferred;";
                message = $"the '{account}' account was authenticated against database '{database}' hosted on '{host}'";

                if (!string.IsNullOrWhiteSpace(port))
                {
                    connString += $"Port={port}";
                }

                // Validating ConnectionString with database.
                ValidationState validationState = ValidateConnectionString(ref message, host, connString, out shouldRetry);
                if (validationState != ValidationState.Unknown || !shouldRetry)
                {
                    return validationState;
                }
            }

            connString = $"Server={host}; Uid={account}; Pwd={password}; SslMode=Preferred;";
            message = $"the '{account}' account is compromised for server '{host}'";

            if (!string.IsNullOrWhiteSpace(port))
            {
                connString += $"Port={port}";
            }

            // Validating ConnectionString without database.
            return ValidateConnectionString(ref message, host, connString, out _);
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
