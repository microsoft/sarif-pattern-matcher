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

        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  ref Dictionary<string, string> groups,
                                                                  ref string message)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref message);
        }

        // public static ValidationState IsValidDynamic(ref Fingerprint fingerprint, ref string message, ref Dictionary<string, string> options)
        // {
        //     return IsValidDynamic(Instance,
        //                           ref fingerprint,
        //                           ref message,
        //                           ref options);
        // }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(ref string matchedPattern,
                                                                             ref Dictionary<string, string> groups,
                                                                             ref string message)
        {
            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("host", out string host) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationResult.NoMatch;
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Id = id,
                    Host = host,
                    Secret = secret,
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string id = fingerprint.Id;
            string host = fingerprint.Host;
            string password = fingerprint.Secret;

            try
            {
                var dbClient = new MongoClient($"mongodb+srv://{id}:{password}@{host}/?connectTimeoutMS=3000");
                List<BsonDocument> databases = dbClient.ListDatabases().ToList();
                message = $"The following databases are compromised: {string.Join(",", databases.Select(q => $"'{q["name"].AsString}'"))}";
                return ValidationState.Authorized;
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
