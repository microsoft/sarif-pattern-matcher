// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public static class MicrosoftSerializedCertificateStoreFileValidator
    {
        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  ref Dictionary<string, string> groups,
                                                                  ref string message)
        {
            Fingerprint fingerprint = default;
            ResultLevelKind resultLevelKind = default;
            ValidationState validationState = CertificateHelper.TryLoadCertificateCollection(matchedPattern,
                                                                                             ref fingerprint,
                                                                                             ref message);

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
