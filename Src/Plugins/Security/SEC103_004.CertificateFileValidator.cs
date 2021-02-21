// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;

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
            string state = null;

            if (groups.ContainsKey("content") && groups["content"].Any(ch => char.IsControl(ch) && ch != '\r' && ch != '\n'))
            {
                groups.Remove("content");
            }

            if (groups.ContainsKey("content"))
            {
                string certificate = groups["content"];
                certificate = certificate.Replace("-----BEGIN CERTIFICATE-----", string.Empty);
                certificate = certificate.Replace("-----END CERTIFICATE-----", string.Empty);
                certificate = certificate.Trim();

                try
                {
                    byte[] rawData = Convert.FromBase64String(certificate);
                    state = CertificateHelper.TryLoadCertificate(rawData,
                                                                 ref thumbprint,
                                                                 ref message);
                }
                catch (Exception e)
                {
                    return ValidatorBase.ReturnUnhandledException(ref message, e);
                }
            }
            else
            {
                state = callCollectionApi ?
                    CertificateHelper.TryLoadCertificateCollection(matchedPattern,
                                                                   ref thumbprint,
                                                                   ref message) :
                    CertificateHelper.TryLoadCertificate(matchedPattern,
                                                         ref thumbprint,
                                                         ref message);

            }

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
