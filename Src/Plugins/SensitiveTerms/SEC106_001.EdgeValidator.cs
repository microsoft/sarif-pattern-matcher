// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SensitiveTerms
{
    public static class EdgeValidator
    {
#pragma warning disable IDE0060 // Remove unused parameter
        public static ValidationState IsValidStatic(ref string matchedPattern,
                                                    ref Dictionary<string, string> groups,
                                                    ref string message,
                                                    out ResultLevelKind resultLevelKind,
                                                    out Fingerprint fingerprint)
        {
#pragma warning restore IDE0060 // Remove unused parameter
            fingerprint = default;
            resultLevelKind = default;

            if (!groups.TryGetValue("target", out string value) || string.IsNullOrWhiteSpace(value))
            {
                return ValidationState.NoMatch;
            }

            return ValidationState.Unknown;
        }
    }
}
