// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using RabbitMQ.Client;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators
{
    public class RabbitMqCredentialsValidator : DynamicValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("host", out FlexMatch host) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret) ||
                !groups.TryGetNonEmptyValue("resource", out FlexMatch resource))
            {
                return ValidationResult.CreateNoMatch();
            }

            string hostValue = FilteringHelpers.StandardizeLocalhostName(host.Value);

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Id = id.Value,
                    Host = hostValue,
                    Secret = secret.Value,
                    Resource = resource.Value,
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
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
