// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using MongoDB.Bson;
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

        // public static ValidationState IsValidDynamic(ref Fingerprint fingerprint, ref string message, ref Dictionary<string, string> options)
        // {
        //     return IsValidDynamic(Instance,
        //                           ref fingerprint,
        //                           ref message,
        //                           ref options);
        // }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                               ref Dictionary<string, string> groups,
                                                               ref string message,
                                                               out ResultLevelKind resultLevelKind,
                                                               out Fingerprint fingerprint)
        {
            fingerprint = default;
            resultLevelKind = default;

            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("host", out string host) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint()
            {
                Id = id,
                Host = host,
                Secret = secret,
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options,
                                                                out ResultLevelKind resultLevelKind)
        {
            resultLevelKind = new ResultLevelKind();

            string id = fingerprint.Id;
            string host = fingerprint.Host;
            string password = fingerprint.Secret;

            try
            {
                var dbClient = new MongoClient($"mongodb+srv://{id}:{password}@{host}/?connectTimeoutMS=3000");
                List<BsonDocument> databases = dbClient.ListDatabases().ToList();
                message = $"The following databases are compromised: {string.Join(",", databases.Select(q => $"'{q["name"].AsString}'"))}";
                return ValidationState.AuthorizedError;
            }
            catch (Exception e)
            {
                if (e is MongoAuthenticationException mae)
                {
                    if (e.Message.StartsWith("Unable to authenticate"))
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: host);
                    }
                }

                return ReturnUnhandledException(ref message, e, asset: host);
            }
        }
    }
}
