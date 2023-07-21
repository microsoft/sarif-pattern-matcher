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
    [ValidatorDescriptor("SEC101/037")]
    public class SqlCredentialsValidator : DynamicValidatorBase
    {
        internal static IRegex RegexEngine;

        private const string ClientIPExpression = @"Client with IP address '[^']+' is not allowed to access the server.";

        private static readonly List<string> AzureHosts = new List<string>
        {
            "database.azure.com",
            "database.cloudapi.de",
            "database.windows.net",
            "database.chinacloudapi.cn",
            "database.secure.windows.net",
        };

        public SqlCredentialsValidator()
        {
            RegexEngine = RE2Regex.Instance;

            // We perform this work in order to force caching of these
            // expressions (an operation which otherwise can cause
            // threading problems).
            RegexEngine.Match(string.Empty, ClientIPExpression);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("host", out FlexMatch host) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret) ||
                !groups.TryGetNonEmptyValue("resource", out FlexMatch resource))
            {
                return ValidationResult.CreateNoMatch();
            }

            if (id.Length > 128 ||
                host.Length > 128 ||
                secret.Length > 128 ||
                resource.Length > 128)
            {
                return ValidationResult.CreateNoMatch();
            }

            string hostValue = FilteringHelpers.StandardizeLocalhostName(host.Value);

            if (hostValue == "localhost" ||
                hostValue.IndexOf("mysql", StringComparison.OrdinalIgnoreCase) != -1 ||
                hostValue.IndexOf("postgres", StringComparison.OrdinalIgnoreCase) != -1)
            {
                return ValidationResult.CreateNoMatch();
            }

            groups.TryGetNonEmptyValue("port", out FlexMatch port);

            var fingerprint = new Fingerprint()
            {
                Id = id.Value,
                Host = hostValue,
                Port = port?.Value,
                Secret = secret.Value,
                Resource = resource.Value,
            };

            SharedUtilities.PopulateAssetFingerprint(AzureHosts, hostValue, ref fingerprint);

            var validationResult = new ValidationResult
            {
                Fingerprint = fingerprint,
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string id = fingerprint.Id;
            string host = fingerprint.Host;
            string secret = fingerprint.Secret;
            string resource = fingerprint.Resource;

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
                $"Server={host};Initial Catalog={resource};User ID={id};Password={secret};" +
                $"Trusted_Connection=False;Encrypt=True;TrustServerCertificate=True;{timeoutString}";
            message = $"the '{id}' account was authenticated against database '{resource}' hosted on '{host}'";

            // Validating ConnectionString with database.
            ValidationState validation = ValidateConnectionString(ref message, host, connString, out bool shouldRetry);
            if (validation != ValidationState.Unknown || !shouldRetry)
            {
                return validation;
            }

            connString =
               $"Server={host};User ID={id};Password={secret};" +
               $"Trusted_Connection=False;Encrypt=True;{timeoutString}";
            message = $"the '{id}' account is compromised for server '{host}'";

            // Validating the connection string without the database.
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

                        if (e.Message.Contains("The server was not found"))
                        {
                            return ReturnUnknownHost(ref message, host);
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
