// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

using Org.BouncyCastle.OpenSsl;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class PemEncodedPrivateKeyValidator : ValidatorBase
    {
        internal static PemEncodedPrivateKeyValidator Instance;

        static PemEncodedPrivateKeyValidator()
        {
            Instance = new PemEncodedPrivateKeyValidator();
        }

        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return ValidatorBase.IsValidStatic(Instance,
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
            groups.TryGetValue("key", out string key);

            key = key.Trim();

            fingerprintText = new Fingerprint
            {
                Key = key,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }
    }
}
