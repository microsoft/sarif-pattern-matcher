// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Text;

using Microsoft.RE2.Managed;

using Npgsql;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class PostgreSqlConnectionStringValidator : ValidatorBase
    {
        internal static PostgreSqlConnectionStringValidator Instance;
        internal static IRegex RegexEngine;

        static PostgreSqlConnectionStringValidator()
        {
            Instance = new PostgreSqlConnectionStringValidator();
            RegexEngine = RE2Regex.Instance;
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

        protected override string IsValidStaticHelper(ref string matchedPattern, ref Dictionary<string, string> groups, ref string failureLevel, ref string fingerprintText, ref string message)
        {
            if (!groups.TryGetValue("host", out string host) ||
                !groups.TryGetValue("database", out string database) ||
                !groups.TryGetValue("account", out string account) ||
                !groups.TryGetValue("password", out string password))
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint()
            {
                Host = host.Replace("\"", string.Empty).Replace(",", ";"),
                Database = database,
                Account = account,
                Password = password,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            NpgsqlConnectionFactory npgsqlConnectionFactory = new NpgsqlConnectionFactory();

            var fingerprint = new Fingerprint(fingerprintText);

            string connString = $"Host={fingerprint.Host};Database={fingerprint.Database};Username={fingerprint.Account};Password={fingerprint.Password}";

            try
            {
                DbConnection postgreSqlconnection = npgsqlConnectionFactory.CreateConnection(connString);
                postgreSqlconnection.Open();
            }
            catch (Exception e)
            {
                // TODO: Are any specific exceptions thrown here?  Npg documentation is lacking

                return ReturnUnhandledException(ref message, e, asset: fingerprint.Host);
            }

            return ReturnAuthorizedAccess(ref message, asset: fingerprint.Host);
        }
    }
}
