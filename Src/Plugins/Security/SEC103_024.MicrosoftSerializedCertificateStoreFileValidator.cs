// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public static class MicrosoftSerializedCertificateStoreFileValidator
    {
        public static IEnumerable<ValidationResult> IsValidStatic(Dictionary<string, FlexMatch> groups)
        {
            string message = string.Empty;
            Fingerprint fingerprint = default;
            ResultLevelKind resultLevelKind = default;
            ValidationState validationState = CertificateHelper.TryLoadCertificateCollection(groups["scanTargetFullPath"].Value,
                                                                                             ref fingerprint,
                                                                                             ref message);

            var validationResult = new ValidationResult
            {
                Message = message,
                Fingerprint = fingerprint,
                ResultLevelKind = resultLevelKind,
                ValidationState = validationState,
            };

            return new[] { validationResult };
        }
    }
}
