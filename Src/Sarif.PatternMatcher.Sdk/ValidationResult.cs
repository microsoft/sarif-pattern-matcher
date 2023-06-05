// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.RE2.Managed;

using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public class ValidationResult
    {
        public ValidationResult()
        {
            ValidationState = ValidationState.Unknown;
        }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore)]
        public string Message { get; set; }

        public string RawSecretHashSha256 { get; set; }

        public Fingerprint Fingerprint { get; set; }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore)]
        public ResultLevelKind ResultLevelKind { get; set; }

        [JsonConverter(typeof(StringEnumConverter))]
        public ValidationState ValidationState { get; set; }

        /// <summary>
        /// Gets or sets the FlexMatch that describes the result SARIF region.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore)]
        public FlexMatch RegionFlexMatch { get; set; }

        public static IEnumerable<ValidationResult> CreateNoMatch()
        {
            return new[]
            {
                new ValidationResult
                {
                    ValidationState = ValidationState.NoMatch,
                },
            };
        }
    }
}
