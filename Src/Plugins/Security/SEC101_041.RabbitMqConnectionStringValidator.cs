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

        public static ValidationState IsValidDynamic(ref string fingerprint, ref string message, ref Dictionary<string, string> options)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options);
        }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetNonEmptyValue("host", out string host) ||
                !groups.TryGetNonEmptyValue("account", out string account) ||
                !groups.TryGetNonEmptyValue("password", out string password) ||
                !groups.TryGetNonEmptyValue("resource", out string resource))
            {
                return ValidationState.NoMatch;
            }

            host = DomainFilteringHelper.StandardizeLocalhostName(host);

            fingerprintText = new Fingerprint()
            {
                Account = account,
                Password = password,
                Host = host,
                Resource = resource,
            }.ToString();

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref string fingerprintText, ref string message, ref Dictionary<string, string> options)
        {
            var fingerprint = new Fingerprint(fingerprintText);
            string host = fingerprint.Host;
            string account = fingerprint.Account;
            string password = fingerprint.Password;
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
