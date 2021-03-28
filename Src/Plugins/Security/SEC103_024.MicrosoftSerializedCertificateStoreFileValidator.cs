// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public static class MicrosoftSerializedCertificateStoreFileValidator
    {
        public static ValidationState IsValidStatic(ref string matchedPattern,
#pragma warning disable IDE0060 // Remove unused parameter
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
#pragma warning restore IDE0060// Remove unused parameter
                                           ref string message,
                                           out Fingerprint fingerprint)
        {
            fingerprint = default;

            return CertificateHelper.TryLoadCertificateCollection(matchedPattern,
                                                               ref fingerprint,
                                                               ref message);
        }
    }
}
