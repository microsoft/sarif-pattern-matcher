// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using MySqlConnector;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class MySqlCredentialsValidator : ValidatorBase
    {
        internal static MySqlCredentialsValidator Instance;

        private static readonly HashSet<string> HostsToExclude = new HashSet<string>
        {
            "localhost",
            "database.windows.net",
            "database.chinacloudapi.cn",
            "postgres.database.azure.com",
            "database.secure.windows.net",
        };

        static MySqlCredentialsValidator()
        {
            Instance = new MySqlCredentialsValidator();
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
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("host", out FlexMatch host) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            groups.TryGetNonEmptyValue("port", out FlexMatch port);
            groups.TryGetNonEmptyValue("resource", out FlexMatch resource);

            string hostValue = FilteringHelpers.StandardizeLocalhostName(host.Value);
            if (hostValue.IndexOf("postgres", StringComparison.OrdinalIgnoreCase) != -1 ||
                HostsToExclude.Any(hostToExclude => hostValue.IndexOf(hostToExclude, StringComparison.OrdinalIgnoreCase) != -1))
            {
                return ValidationResult.CreateNoMatch();
            }

            var fingerprint = new Fingerprint()
            {
                Id = id.Value,
                Host = hostValue,
                Port = port?.Value,
                Secret = secret.Value,
                Resource = resource?.Value,
            };

            SharedUtilities.PopulateAssetFingerprint(hostValue, ref fingerprint);
            var validationResult = new ValidationResult
            {
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
