// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    [ValidatorDescriptor("SEC101/033")]
    public class MongoDbCredentialsValidator : StaticValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("host", out FlexMatch host) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Id = id.Value,
                    Host = host.Value,
                    Secret = secret.Value,
                },
            };

            return new[] { validationResult };
        }

        // protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
        //                                                         ref string message,
        //                                                         IDictionary<string, string> options,
        //                                                         ref ResultLevelKind resultLevelKind)
        // {
        //     string id = fingerprint.Id;
        //     string host = fingerprint.Host;
        //     string password = fingerprint.Secret;
        //     try
        //     {
        //         var dbClient = new MongoClient($"mongodb+srv://{id}:{password}@{host}/?connectTimeoutMS=3000");
        //         List<BsonDocument> databases = dbClient.ListDatabases().ToList();
        //         message = $"The following databases are compromised: {string.Join(",", databases.Select(q => $"'{q["name"].AsString}'"))}";
        //         return ValidationState.Authorized;
        //     }
        //     catch (Exception e)
        //     {
        //         if (e is MongoAuthenticationException mae)
        //         {
        //             if (e.Message.StartsWith("Unable to authenticate"))
        //             {
        //                 return ReturnUnauthorizedAccess(ref message, asset: host);
        //             }
        //         }
        //         return ReturnUnhandledException(ref message, e, asset: host);
        //     }
        // }
    }
}
