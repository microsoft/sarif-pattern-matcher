// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.HelpersUtilitiesAndExtensions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public static class CertificateFileValidator
    {
#pragma warning disable IDE0060 // Remove unused parameter

        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprintText,
                                           ref string message)
        {
#pragma warning restore IDE0060

            bool callCollectionApi = groups.ContainsKey("bundle");

            string thumbprint = null;
            string state = callCollectionApi ?
                CertificateHelper.TryLoadCertificateCollection(matchedPattern,
                                                               ref thumbprint,
                                                               ref message) :
                CertificateHelper.TryLoadCertificate(matchedPattern,
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
