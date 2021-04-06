// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using RabbitMQ.Client;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class RabbitMqConnectionStringValidator : ValidatorBase
    {
        internal static RabbitMqConnectionStringValidator Instance;

        static RabbitMqConnectionStringValidator()
        {
            Instance = new RabbitMqConnectionStringValidator();
        }

        public static ValidationState IsValidStatic(ref string matchedPattern,
                                                    ref Dictionary<string, string> groups,
                                                    ref string failureLevel,
                                                    ref string message,
                                                    out Fingerprint fingerprint)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref failureLevel,
                                 ref message,
                                 out fingerprint);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint, ref string message, ref Dictionary<string, string> options)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options);
        }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                               ref Dictionary<string, string> groups,
                                                               ref string failureLevel,
                                                               ref string message,
                                                               out Fingerprint fingerprint)
        {
            fingerprint = default;

            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("host", out string host) ||
                !groups.TryGetNonEmptyValue("secret", out string secret) ||
                !groups.TryGetNonEmptyValue("resource", out string resource))
            {
                return ValidationState.NoMatch;
            }

            host = DomainFilteringHelper.StandardizeLocalhostName(host);

            fingerprint = new Fingerprint()
            {
                Id = id,
                Host = host,
                Secret = secret,
                Resource = resource,
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint, ref string message, ref Dictionary<string, string> options)
        {
            string host = fingerprint.Host;
            string account = fingerprint.Id;
            string password = fingerprint.Secret;
            string resource = fingerprint.Resource;

            if (DomainFilteringHelper.LocalhostList.Contains(host))
            {
                return ValidationState.Unknown;
            }

            try
            {
                var factory = new ConnectionFactory
                {
                    Uri = new Uri($"amqp://{account}:{password}@{host}/{resource}"),
                };

                using IConnection conn = factory.CreateConnection();
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: host, account: account);
            }

            return ValidationState.AuthorizedError;
        }
    }
}
