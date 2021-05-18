// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities
{
    public static class FilteringHelpers
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

        public static ValidationState HostExclusion(string host, IEnumerable<string> hostList = null)
        {
            if (hostList == null || !hostList.Any())
            {
                return ValidationState.Unknown;
            }

            string lowerHost = host.ToLower();

            // Other rules will handle these cases.
            foreach (string hostToExclude in hostList)
            {
                if (lowerHost.Contains(hostToExclude.ToLower()))
                {
                    return ValidationState.NoMatch;
                }
            }

            return ValidationState.Unknown;
        }

        public static bool LikelyPowershellVariable(string input)
        {
            if (input.Length < 4)
            {
                // Not enough space for a variable name in the string
                return false;
            }

            if (input[0] != '$')
            {
                return false;
            }

            if (input[1] != '(')
            {
                return false;
            }

            if (input[input.Length - 1] != ')')
            {
                return false;
            }

            return true;
        }
    }
}
