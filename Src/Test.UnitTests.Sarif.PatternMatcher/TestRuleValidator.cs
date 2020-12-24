// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class TestRuleValidator
    {
        public static string IsValid(
            string matchedPattern,
            ref bool performDynamicValidation,
            ref string failureLevel)
        {
            performDynamicValidation = false;
            return matchedPattern + "#" + performDynamicValidation;
        }
    }
}
