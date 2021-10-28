// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.AzureDevOpsConfiguration
{
    public class DoNotGrantAllPipelinesAccessToVariableGroupsWithSecretsValidator : StaticValidatorBase
    {
        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("org", out FlexMatch org) ||
                !groups.TryGetNonEmptyValue("project", out FlexMatch project) ||
                !groups.TryGetNonEmptyValue("variableGroupId", out FlexMatch variableGroupId) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Host = org.Value,
                    Resource = project.Value,
                    Id = variableGroupId.Value,
                    Platform = nameof(AssetPlatform.AzureDevOps),
                },
                RegionFlexMatch = secret,
                ValidationState = ValidationState.Authorized,
            };
            return new[] { validationResult };
        }
    }
}
