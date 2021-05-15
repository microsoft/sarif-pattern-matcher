// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net.Mail;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public static class EmailAddressValidator
    {
#pragma warning disable IDE0060 // Unused parameter.

        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  Dictionary<string, FlexMatch> groups)
#pragma warning restore IDE0060 // Unused parameter.
        {
            try
            {
                var addr = new MailAddress(matchedPattern);
                if (addr.Address == matchedPattern)
                {
                    var validationResult = new ValidationResult
                    {
                        ValidationState = ValidationState.Unknown,
                    };

                    string[] parts = matchedPattern.Split('@');

                    if (parts.Length == 2)
                    {
                        string id = parts[0];
                        string host = parts[1];
                        validationResult.Fingerprint = new Fingerprint()
                        {
                            Id = parts[0],
                            Host = parts[1],
                        };

                        groups.Add("id", new FlexMatch() { Value = id });
                        groups.Add("host", new FlexMatch() { Value = host });
                    }

                    return new[] { validationResult };
                }
            }
            catch
            {
                return ValidationResult.CreateNoMatch();
            }

            return ValidationResult.CreateNoMatch();
        }
    }
}
