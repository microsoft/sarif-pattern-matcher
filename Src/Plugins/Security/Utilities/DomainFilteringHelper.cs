// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities
{
    public static class DomainFilteringHelper
    {
        public static readonly HashSet<string> LocalhostList = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "localhost",
            "(local)",
            "127.0.0.1",
            ".",
        };

        public static string StandardizeLocalhostName(string hostName)
        {
            if (LocalhostList.Contains(hostName))
            {
                return "localhost";
            }

            return hostName;
        }

        public static string HostExclusion(string host, IEnumerable<string> hostList = null)
        {
            if (hostList == null || !hostList.Any())
            {
                return nameof(ValidationState.Unknown);
            }

            string lowerHost = host.ToLower();

            // Other rules will handle these cases.
            foreach (string hostToExclude in hostList)
            {
                if (lowerHost.Contains(hostToExclude.ToLower()))
                {
                    return nameof(ValidationState.NoMatch);
                }
            }

            return nameof(ValidationState.Unknown);
        }
    }
}
