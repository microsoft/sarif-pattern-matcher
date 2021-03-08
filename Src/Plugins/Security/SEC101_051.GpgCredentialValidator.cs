﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GpgCredentialValidator : ValidatorBase
    {
        internal static GpgCredentialValidator Instance;

        static GpgCredentialValidator()
        {
            Instance = new GpgCredentialValidator();
        }

        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref failureLevel,
                                 ref fingerprint,
                                 ref message);
        }

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetNonEmptyValue("password", out string password))
            {
                return nameof(ValidationState.NoMatch);
            }

            groups.TryGetNonEmptyValue("account", out string account);

            fingerprintText = new Fingerprint()
            {
                Account = account,
                Password = password,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }
    }
}