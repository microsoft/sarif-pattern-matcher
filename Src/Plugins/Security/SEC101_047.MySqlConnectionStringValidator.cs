// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using MySqlConnector;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Internal
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
            "postgres.database.azure.com",
        };

        static MySqlConnectionStringValidator()
        {
            Instance = new MySqlConnectionStringValidator();
            RegexEngine = RE2Regex.Instance;
        }

        public static ValidationState IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string message,
                                           out Fingerprint fingerprint)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref failureLevel,
                                 ref message,
                                 out fingerprint);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint, ref string message, ref Dictionary<string, string> options)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options);
        }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string message,
                                                      out Fingerprint fingerprint)
        {
            fingerprint = default;
            if (!groups.TryGetNonEmptyValue("account", out string account) ||
                !groups.TryGetNonEmptyValue("password", out string password))
            {
                return ValidationState.NoMatch;
            }

            // Our matches can sometimes fail to find a host (due to it being constructed in code)
            // However, the credentials can still be valid, so we should return "unknown".
            // Grab the empty host here and then short circuit in dynamic validation.

            fingerprint = new Fingerprint()
            {
                Account = account,
                Secret = password,
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

            host = DomainFilteringHelper.StandardizeLocalhostName(host);

            ValidationState exclusionResult = DomainFilteringHelper.HostExclusion(host, HostsToExclude);

            if (exclusionResult == ValidationState.NoMatch)
            {
                return exclusionResult;
            }

            fingerprint.Host = host.Replace("\"", string.Empty).Replace(",", ";");
            fingerprint.Resource = database;
            fingerprint.Port = port;
            fingerprint.Platform = SharedUtilities.GetDatabasePlatformFromHost(fingerprint.Host, out _);

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                       ref string message,
                                                       ref Dictionary<string, string> options)
        {
            string host = fingerprint.Host;
            string database = fingerprint.Resource;
            string port = fingerprint.Port;
            string account = fingerprint.Account;
            string password = fingerprint.Secret;

            if (string.IsNullOrWhiteSpace(host) ||
                string.IsNullOrWhiteSpace(database) ||
                DomainFilteringHelper.LocalhostList.Contains(host))
            {
                return ValidationState.Unknown;
            }

            var connectionStringBuilder = new StringBuilder();
            connectionStringBuilder.Append($"Server={host}; Database={database}; Uid={account}; Pwd={password}; SslMode=Preferred;");
            message = $"the '{account}' account was authenticated against database '{database}' hosted on '{host}'";

            if (!string.IsNullOrWhiteSpace(port))
            {
                connectionStringBuilder.Append($"Port={port}");
            }

            try
            {
                using var connection = new MySqlConnection(connectionStringBuilder.ToString());
                connection.Open();
            }
            catch (Exception e)
            {
                if (e is MySqlException mysqlException)
                {
                    if (mysqlException.ErrorCode == MySqlErrorCode.AccessDenied)
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

            return ValidationState.AuthorizedError;
        }
    }
}
