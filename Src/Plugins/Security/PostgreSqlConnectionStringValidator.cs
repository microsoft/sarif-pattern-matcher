// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Data.Common;

using Npgsql;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class PostgreSqlConnectionStringValidator : ValidatorBase
    {
        internal static PostgreSqlConnectionStringValidator Instance;

        static PostgreSqlConnectionStringValidator()
        {
            Instance = new PostgreSqlConnectionStringValidator();
        }

        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return ValidatorBase.IsValidStatic(Instance,
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

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetValue("host", out string host) ||
                !groups.TryGetValue("port", out string port) ||
                !groups.TryGetValue("account", out string account) ||
                !groups.TryGetValue("password", out string password))
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint()
            {
                Host = host,
                Port = port,
                Account = account,
                Password = password,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            var fingerprint = new Fingerprint(fingerprintText);

            string connString;
            if (string.IsNullOrWhiteSpace(fingerprint.Port))
            {
                connString = $"Host={fingerprint.Host};Username={fingerprint.Account};Password={fingerprint.Password};Ssl Mode=Require";
            }
            else
            {
                connString = $"Host={fingerprint.Host};Port={fingerprint.Port};Username={fingerprint.Account};Password={fingerprint.Password};Ssl Mode=Require";
            }

            try
            {
                using var postgreSqlconnection = new NpgsqlConnection(connString);
                postgreSqlconnection.Open();
            }
            catch (Exception e)
            {
                if (e is PostgresException postgresException)
                {
                    // Database does not exist, but the creds are valid
                    if (postgresException.SqlState == "3D000")
                    {
                        return ReturnAuthorizedAccess(ref message, asset: fingerprint.Host);
                    }

                    // password authentication failed for user
                    if (postgresException.SqlState == "28P01")
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: fingerprint.Host);
                    }
                }

                return ReturnUnhandledException(ref message, e, asset: fingerprint.Host);
            }

            return ReturnAuthorizedAccess(ref message, asset: fingerprint.Host);
        }
    }
}
