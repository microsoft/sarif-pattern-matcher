// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net.Mail;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class UrlValidator : StaticValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            string fullMatchText = groups["0"].Value;

            if (!Uri.TryCreate(fullMatchText, UriKind.Absolute, out Uri uri))
            {
                return ValidationResult.CreateNoMatch();
            }

            string query = uri.Query;
            string path = uri.PathAndQuery;

            if (path.EndsWith(query))
            {
                path = path.Substring(0, path.Length - query.Length);
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Host = uri.Host,
                    Scheme = uri.Scheme,
                    Path = path,
                    Part = query,
                    Port = uri.Port.ToString(),
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }
    }
}
