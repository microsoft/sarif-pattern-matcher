// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

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
#pragma warning disable CA2211 // Non-constant fields should not be visible
        public static IsValidStaticDelegate OverrideIsValidStatic;

        [ThreadStatic]
        public static IsValidDynamicDelegate OverrideIsValidDynamic;
#pragma warning restore CA2211 // Non-constant fields should not be visible

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            return OverrideIsValidStatic == null ? null : OverrideIsValidStatic(groups);
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            return OverrideIsValidDynamic == null ? 0 : OverrideIsValidDynamic(ref fingerprint, ref message, options, ref resultLevelKind);
        }
    }
}
