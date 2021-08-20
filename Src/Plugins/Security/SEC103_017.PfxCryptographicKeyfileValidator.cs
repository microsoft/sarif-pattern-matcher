// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class PfxCryptographicKeyfileValidator : StaticValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            groups.TryGetValue("content", out FlexMatch content);

            if (!string.IsNullOrWhiteSpace(content.Value) &&
                !content.Value.String.Any(ch => char.IsControl(ch) && ch != '\r' && ch != '\n'))
            {
                // This condition indicates that we have textual (PEM-encoded) data.
                // These certificates are handled by the SecurePlaintextSecrets rules.
                return ValidationResult.CreateNoMatch();
            }

            string message = string.Empty;
            Fingerprint fingerprint = default;
            ResultLevelKind resultLevelKind = default;
            ValidationState validationState = CertificateHelper.TryLoadCertificate(groups["scanTargetFullPath"].Value,
                                                                                   ref fingerprint,
                                                                                   ref message,
                                                                                   ref resultLevelKind);

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
