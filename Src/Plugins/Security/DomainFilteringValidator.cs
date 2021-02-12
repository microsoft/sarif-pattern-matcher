// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.HelpersUtiliesAndExtensions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public abstract class DomainFilteringValidator : ValidatorBase
    {
        public static string IsValidStatic(DomainFilteringValidator validator,
                                           ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            validator.MatchCleanup(ref matchedPattern,
                                    ref groups,
                                    ref failureLevel,
                                    ref fingerprint,
                                    ref message);

            string state = validator.HostExclusion(ref groups);

            if (state == nameof(ValidationState.NoMatch))
            {
                return state;
            }

            return PerformValidationAndCheckCache(validator, ref matchedPattern, ref groups, ref failureLevel, ref fingerprint, ref message);
        }

        public static void StandardizeLocalhostName(Dictionary<string, string> groups, string hostKey = "host")
        {
            if (groups.TryGetNonEmptyValue(hostKey, out string host))
            {
                if (LocalhostList.Contains(host))
                {
                    groups[hostKey] = "localhost";
                }
            }
        }

        public virtual string HostExclusion(ref Dictionary<string, string> groups, IEnumerable<string> hostList = null, string hostKey = "host")
        {
            if (hostList == null)
            {
                return nameof(ValidationState.Unknown);
            }

            if (!groups.TryGetNonEmptyValue(hostKey, out string host))
            {
                return nameof(ValidationState.NoMatch);
            }

            // Other rules will handle these cases.
            foreach (string hostToExclude in hostList)
            {
                if (host.EndsWith(hostToExclude, StringComparison.OrdinalIgnoreCase))
                {
                    return nameof(ValidationState.NoMatch);
                }
            }

            return nameof(ValidationState.Unknown);
        }
    }
}
