// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net.Mail;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    internal static class EmailAddressValidator
    {
        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprintText,
                                           ref string message)
        {
            try
            {
                var addr = new MailAddress(matchedPattern);
                if (addr.Address == matchedPattern)
                {
                    return nameof(ValidationState.Unknown);
                }
            }
            catch
            {
                return nameof(ValidationState.NoMatch);
            }

            return nameof(ValidationState.NoMatch);
        }
    }
}
