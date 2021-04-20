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
        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  ref Dictionary<string, string> groups,
                                                                  ref string message)
        {
            groups.TryGetValue("content", out string content);

            if (!string.IsNullOrWhiteSpace(content) &&
                !content.Any(ch => char.IsControl(ch) && ch != '\r' && ch != '\n'))
            {
                // This condition indicates that we have textual (PEM-encoded) data.
                // These certificates are handled by the SecurePlaintextSecrets rules.
                return ValidationResult.NoMatch;
            }

            Fingerprint fingerprint = default;
            ResultLevelKind resultLevelKind = default;
            ValidationState validationState = CertificateHelper.TryLoadCertificate(matchedPattern,
                                                                                   ref fingerprint,
                                                                                   ref message,
                                                                                   ref resultLevelKind);

            var validationResult = new ValidationResult
            {
                Fingerprint = fingerprint,
                ResultLevelKind = resultLevelKind,
                ValidationState = validationState,
            };

            return new[] { validationResult };
        }
    }
}
