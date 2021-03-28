// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net.Mail;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public static class EmailAddressValidator
    {
#pragma warning disable IDE0060 // Unused parameter.

        public static ValidationState IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string message,
                                           out Fingerprint fingerprint)
#pragma warning restore IDE0060 // Unused parameter.
        {
            fingerprint = default;
            try
            {
                var addr = new MailAddress(matchedPattern);
                if (addr.Address == matchedPattern)
                {
                    string[] parts = matchedPattern.Split('@');
                    if (parts.Length == 2)
                    {
                        fingerprint = new Fingerprint()
                        {
                            Account = parts[0],
                            Host = parts[1],
                        };
                    }

                    return ValidationState.Unknown;
                }
            }
            catch
            {
                return ValidationState.NoMatch;
            }

            return ValidationState.NoMatch;
        }
    }
}
