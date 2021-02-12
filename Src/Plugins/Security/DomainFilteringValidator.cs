// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.HelpersUtiliesAndExtensions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public abstract class DomainFilteringValidator : ValidatorBase
    {
        public static readonly HashSet<string> LocalhostList = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "localhost",
            "(local)",
            "127.0.0.1",
        };

        public static string IsValidStatic(DomainFilteringValidator validator,
                                           ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {

            string state = validator.HostExclusion(ref groups);

            if (state == nameof(ValidationState.NoMatch))
            {
                return state;
            }

            return ValidatorBase.IsValidStatic(validator, ref matchedPattern, ref groups, ref failureLevel, ref fingerprint, ref message);
        }

        public static string StandardizeLocalhostName(string hostName)
        {
            if (LocalhostList.Contains(hostName))
            {
                return "localhost";
            }

            return hostName;
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
