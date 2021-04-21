﻿// Copyright (c) Microsoft. All rights reserved.
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

        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  Dictionary<string, string> groups)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 groups);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     Dictionary<string, string> options,
                                                     ref ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  options,
                                  ref resultLevelKind);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(ref string matchedPattern,
                                                                             Dictionary<string, string> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("host", out string host) ||
                !groups.TryGetNonEmptyValue("secret", out string secret) ||
                !groups.TryGetNonEmptyValue("resource", out string resource))
            {
                return ValidationResult.CreateNoMatch();
            }

            host = FilteringHelpers.StandardizeLocalhostName(host);

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Id = id,
                    Host = host,
                    Secret = secret,
                    Resource = resource,
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                Dictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string host = fingerprint.Host;
            string account = fingerprint.Id;
            string password = fingerprint.Secret;
            string resource = fingerprint.Resource;

            if (FilteringHelpers.LocalhostList.Contains(host))
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

            return ValidationState.Authorized;
        }
    }
}
