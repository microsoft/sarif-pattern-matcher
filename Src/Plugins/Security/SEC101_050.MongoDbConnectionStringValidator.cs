// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using MongoDB.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Internal
{
    public class MongoDbConnectionStringValidator : ValidatorBase
    {
        internal static MongoDbConnectionStringValidator Instance;

        static MongoDbConnectionStringValidator()
        {
            Instance = new MongoDbConnectionStringValidator();
        }

        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref failureLevel,
                                 ref fingerprint,
                                 ref message);
        }

        public static string IsValidDynamic(ref string fingerprint, ref string message, ref Dictionary<string, string> options)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options);
        }

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetNonEmptyValue("account", out string account) ||
                !groups.TryGetNonEmptyValue("password", out string password) ||
                !groups.TryGetNonEmptyValue("host", out string host))
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint()
            {
                Account = account,
                Password = password,
                Host = host,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message,
                                                       ref Dictionary<string, string> options)
        {
            var fingerprint = new Fingerprint(fingerprintText, false);

            string host = fingerprint.Host;
            string account = fingerprint.Account;
            string password = fingerprint.Password;

            try
            {
                var dbClient = new MongoClient($"mongodb+srv://{account}:{password}@{host}/?connectTimeoutMS=3000");
                dbClient.ListDatabases();
            }
            catch (Exception e)
            {
                if (e is MongoAuthenticationException mae)
                {
                    if (e.Message.Contains("Unable to authenticate"))
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: host);
                    }
                }

                return ReturnUnhandledException(ref message, e, asset: host);
            }

            return ReturnAuthorizedAccess(ref message, asset: host, account: account);
        }
    }
}
