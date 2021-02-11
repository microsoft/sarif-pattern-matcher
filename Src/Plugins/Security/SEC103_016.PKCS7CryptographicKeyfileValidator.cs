// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public static class PKCS7CryptographicKeyfileValidator
    {
        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprintText,
                                           ref string message)
        {
            groups["bundle"] = string.Empty;

            return CertificateFileValidator.IsValidStatic(ref matchedPattern,
                                                          ref groups,
                                                          ref failureLevel,
                                                          ref fingerprintText,
                                                          ref message);
        }
    }
}
