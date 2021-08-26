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
    public class PostgreSqlCredentialsValidator : DynamicValidatorBase
    {
        private static readonly HashSet<string> HostsToExclude = new HashSet<string>
        {
            "localhost",
            "database.windows.net",
            "database.chinacloudapi.cn",
            "database.secure.windows.net",
        };

        private static readonly List<string> AzureHosts = new List<string>
        {
            "database.azure.com",
            "postgres.database.azure.com",
        };

        private const string publicNetworkDisabled = "The public network access on this server is disabled";

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
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
            string idValue = id.Value;

            // Username must be in the form <username>@<hostname> to communicate with Azure.
            // If the username does not contain a host name, we can't connect.
            if (AzureHosts.Any(azHosts => hostValue.IndexOf(azHosts, StringComparison.OrdinalIgnoreCase) != -1) &&
                !idValue.Contains("@"))
            {
                return ValidationResult.CreateNoMatch();
            }

            if (hostValue.Equals("tcp", StringComparison.OrdinalIgnoreCase) ||
                hostValue.IndexOf("mysql", StringComparison.OrdinalIgnoreCase) != -1 ||
                HostsToExclude.Any(hostToExclude => hostValue.IndexOf(hostToExclude, StringComparison.OrdinalIgnoreCase) != -1))
            {
                return ValidationResult.CreateNoMatch();
            }

            var fingerprint = new Fingerprint()
            {
                Id = idValue,
                Host = hostValue,
                Port = port?.Value,
                Secret = secret.Value,
                Resource = resource?.Value,
            };

            SharedUtilities.PopulateAssetFingerprint(AzureHosts, hostValue, ref fingerprint);
            var validationResult = new ValidationResult
            {
                Fingerprint = fingerprint,
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
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

            string timeoutString = "Timeout=3;";
            if (options.TryGetNonEmptyValue("retry", out string retry) && retry == bool.TrueString)
            {
                timeoutString = "Timeout=15;";
            }

            var connectionStringBuilder = new StringBuilder();
            message = $"the '{account}' account is compromised for server '{host}'";
            connectionStringBuilder.Append($"Host={host};Username={account};Password={password};Ssl Mode=Require;{timeoutString}");

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

                    // Public Network access disabled.
                    if (postgresException.SqlState == "28000" && postgresException.MessageText.StartsWith(publicNetworkDisabled))
                    {
                        return ReturnUnknownHost(ref message, host);
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
