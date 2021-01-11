// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    internal static class PKCS7CryptographicKeyfileValidator
    {
#pragma warning disable IDE0060 // Remove unused parameter
        public static string IsValid(
            ref string matchedPattern,
            ref Dictionary<string, string> groups,
            ref bool performDynamicValidation,
            ref string failureLevel,
            ref string fingerprint)
        {
#pragma warning restore IDE0060

            // This plugin does not perform any dynamic validation.
            // We therefore set this setting to false. This is a
            // clue to the caller not to warn the user that, e.g.,
            // dynamic analysis was available but not exercised.
            performDynamicValidation = false;

            string thumbprint = string.Empty;
            string validationState = CertificateHelper.TryLoadCertificateCollection(matchedPattern, ref thumbprint);
            if (!string.IsNullOrEmpty(thumbprint))
            {
                fingerprint = $"[thumbprint={thumbprint}]";
            }

            return validationState;
        }
    }
}
