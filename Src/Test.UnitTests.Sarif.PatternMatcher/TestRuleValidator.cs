// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class TestRuleValidator
    {
        public delegate IEnumerable<ValidationResult> IsValidStaticDelegate(Dictionary<string, FlexMatch> groups);

        public delegate ValidationState IsValidDynamicDelegate(ref Fingerprint fingerprint,
                                                               ref string message,
                                                               Dictionary<string, string> options,
                                                               ref ResultLevelKind resultLevelKind);

        [ThreadStatic]
        public static IsValidStaticDelegate OverrideIsValidStatic;

        [ThreadStatic]
        public static IsValidDynamicDelegate OverrideIsValidDynamic;

        public static IEnumerable<ValidationResult> IsValidStatic(Dictionary<string, FlexMatch> groups)
        {
            if (OverrideIsValidStatic == null) { return null; }
            return OverrideIsValidStatic(groups);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     Dictionary<string, string> options,
                                                     ref ResultLevelKind resultLevelKind)
        {
            if (OverrideIsValidDynamic == null) { return 0; }
            return OverrideIsValidDynamic(ref fingerprint, ref message, options, ref resultLevelKind);
        }
    }
}
