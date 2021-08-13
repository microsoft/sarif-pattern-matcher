// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class TestRuleValidator : DynamicValidatorBase
    {
        public delegate IEnumerable<ValidationResult> IsValidStaticDelegate(IDictionary<string, FlexMatch> groups);

        public delegate ValidationState IsValidDynamicDelegate(ref Fingerprint fingerprint,
                                                               ref string message,
                                                               IDictionary<string, string> options,
                                                               ref ResultLevelKind resultLevelKind);

        [ThreadStatic]
        public static IsValidStaticDelegate OverrideIsValidStatic;

        [ThreadStatic]
        public static IsValidDynamicDelegate OverrideIsValidDynamic;

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (OverrideIsValidStatic == null) { return null; }
            return OverrideIsValidStatic(groups);
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            if (OverrideIsValidDynamic == null) { return 0; }
            return OverrideIsValidDynamic(ref fingerprint, ref message, options, ref resultLevelKind);
        }
    }
}
