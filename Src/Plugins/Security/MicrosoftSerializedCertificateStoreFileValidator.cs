// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    internal static class MicrosoftSerializedCertificateStoreFileValidator
    {
#pragma warning disable IDE0060 // Remove unused parameter
        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprintText,
                                           ref string message)
        {
#pragma warning restore IDE0060
            groups["bundle"] = string.Empty;

            return CertificateFileValidator.IsValidStatic(ref matchedPattern,
                                                          ref groups,
                                                          ref failureLevel,
                                                          ref fingerprintText,
                                                          ref message);
        }
    }
}
