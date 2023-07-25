// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using RabbitMQ.Client;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    [ValidatorDescriptor("SEC101/041")]
    public class RabbitMqCredentialsValidator : DynamicValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            groups.TryGetValue("id", out FlexMatch id);
            groups.TryGetValue("host", out FlexMatch host);
            groups.TryGetValue("secret", out FlexMatch secret);
            groups.TryGetValue("resource", out FlexMatch resource);
            groups.TryGetValue("port", out FlexMatch port);

            if (FilteringHelpers.PasswordIsInCommonVariableContext(secret.Value))
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
                    Port = port?.Value,
                    Secret = secret.Value,
                    Resource = resource?.Value,
                },
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string host = fingerprint.Host;
            string port = fingerprint.Port;
            string account = fingerprint.Id;
            string password = fingerprint.Secret;
            string resource = fingerprint.Resource;

            if (FilteringHelpers.LocalhostList.Contains(host))
            {
                return ValidationState.Unknown;
            }

            host += string.IsNullOrWhiteSpace(port) ? string.Empty : $":{port}";

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
