// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using MongoDB.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    [ValidatorDescriptor("SEC101/033")]
    public class MongoDbCredentialsValidator : DynamicValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch id = groups["id"];
            FlexMatch host = groups["host"];
            FlexMatch secret = groups["secret"];
            FlexMatch protocol = groups["protocol"];
            groups.TryGetValue("options", out FlexMatch options);

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Id = id.Value,
                    Host = host.Value,
                    Secret = secret.Value,
                    Scheme = protocol.Value,
                    QueryString = options?.Value,
                },
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
            string password = fingerprint.Secret;
            string protocol = fingerprint.Scheme;
            string queryString = fingerprint.QueryString;

            try
            {
                string connectionString = $"{protocol}://{id}:{password}@{host}";

                string timeoutOption = "serverSelectionTimeoutMS=3000&connectTimeoutMS=3000&socketTimeoutMS=3000";

                connectionString += string.IsNullOrEmpty(queryString) ?
                                    $"/?{timeoutOption}" :
                                    $"{queryString}&{timeoutOption}";

                var dbClient = new MongoClient(connectionString);

                var databases = dbClient.ListDatabases().ToList();

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
