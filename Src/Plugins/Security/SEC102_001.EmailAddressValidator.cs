﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net.Mail;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class EmailAddressValidator : StaticValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("host", out FlexMatch host))
            {
                return ValidationResult.CreateNoMatch();
            }

            string candidateAddress = $"{id}.Value@{host?.Value}";

            try
            {
                var actualAddress = new MailAddress(candidateAddress);
                if (actualAddress.Address == candidateAddress)
                {
                    var validationResult = new ValidationResult
                    {
                        Fingerprint = new Fingerprint()
                        {
                            Id = id.Value,
                            Host = host.Value,
                        },
                        ValidationState = ValidationState.Unknown,
                    };

                    return new[] { validationResult };
                }

                return ValidationResult.CreateNoMatch();
            }
            catch
            {
                return ValidationResult.CreateNoMatch();
            }
        }
    }
}
