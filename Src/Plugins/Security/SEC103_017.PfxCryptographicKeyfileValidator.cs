// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public static class PfxCryptographicKeyfileValidator
    {
        public static ValidationState IsValidStatic(ref string matchedPattern,
                                                    ref Dictionary<string, string> groups,
#pragma warning disable IDE0060 // Remove unused parameter
                                                    ref string failureLevel,
#pragma warning restore IDE0060
                                                    ref string message,
                                                    out Fingerprint fingerprint)
        {
            fingerprint = default;

            groups.TryGetValue("content", out string content);

            if (!string.IsNullOrWhiteSpace(content) &&
                !content.Any(ch => char.IsControl(ch) && ch != '\r' && ch != '\n'))
            {
                // This condition indicates that we have textual (PEM-encoded) data.
                // These certificates are handled by the SecurePlaintextSecrets rules.
                return ValidationState.NoMatch;
            }

            return CertificateHelper.TryLoadCertificate(matchedPattern,
                                                         ref fingerprint,
                                                         ref message);
        }
    }
}
