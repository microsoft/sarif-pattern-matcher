// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public static class MicrosoftSerializedCertificateStoreFileValidator
    {
        public static string IsValidStatic(ref string matchedPattern,
#pragma warning disable IDE0060 // Remove unused parameter
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
#pragma warning restore IDE0060// Remove unused parameter
                                           ref string fingerprintText,
                                           ref string message)
        {
            string thumbprint = null;

            string state =
                CertificateHelper.TryLoadCertificateCollection(matchedPattern,
                                                               ref thumbprint,
                                                               ref message);

            if (thumbprint != null)
            {
                fingerprintText = new Fingerprint()
                {
                    Thumbprint = thumbprint,
                }.ToString();
            }

            return state;
        }
    }
}
