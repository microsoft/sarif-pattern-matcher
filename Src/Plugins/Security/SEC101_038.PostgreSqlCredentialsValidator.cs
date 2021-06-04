// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Npgsql;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class PostgreSqlCredentialsValidator : ValidatorBase
    {
        internal static PostgreSqlCredentialsValidator Instance;

        private static readonly HashSet<string> HostsToExclude = new HashSet<string>
        {
            "localhost",
            "database.windows.net",
            "database.chinacloudapi.cn",
        };

        static PostgreSqlCredentialsValidator()
        {
            Instance = new PostgreSqlCredentialsValidator();
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
            if (hostValue.IndexOf("mysql", StringComparison.OrdinalIgnoreCase) != -1 ||
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

            if (FilteringHelpers.LocalhostList.Contains(host))
            {
                return ValidationState.Unknown;
            }

            var connectionStringBuilder = new StringBuilder();
            message = $"the '{account}' account is compromised for server '{host}'";
            connectionStringBuilder.Append($"Host={host};Username={account};Password={password};Ssl Mode=Require;");

            if (!string.IsNullOrWhiteSpace(port))
            {
                connectionStringBuilder.Append($"Port={port};");
            }

            if (!string.IsNullOrWhiteSpace(database))
            {
                message = $"the '{account}' account was authenticated against database '{database}' hosted on '{host}'";
                connectionStringBuilder.Append($"Database={database};");
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
                        return ReturnAuthorizedAccess(ref message, asset: host);
                    }

                    // password authentication failed for user
                    if (postgresException.SqlState == "28P01")
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: host);
                    }
                }

                if (e?.InnerException is TimeoutException)
                {
                    // default timeout is more than long enough to establish a connection, if we
                    // timeout, it's more likely that the server silently rejected our attempt to connect
                    return ReturnUnknownAuthorization(ref message, asset: host);
                }

                return ReturnUnhandledException(ref message, e.InnerException ?? e, asset: host);
            }

            return ValidationState.Authorized;
        }
    }
}
