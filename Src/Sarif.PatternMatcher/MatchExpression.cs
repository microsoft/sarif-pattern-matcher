// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class MatchExpression
    {
        public IList<RegexMetadata> RegexMetadata { get; set; }

        public List<string> SniffLiterals { get; set; }

        public IList<string> IntrafileRegexes { get; set; }

        public IList<string> SingleLineRegexes { get; set; }

        public string Id { get; set; }

        public string SubId { get; set; }

        public string Index { get; set; }

        public string Name { get; set; }

        public string DeprecatedName { get; set; }

        public string HelpUri { get; set; }

        public string Message { get; set; }

        public RuleEnabledState RuleEnabledState { get; set; }

        public FailureLevel Level { get; set; }

        public ResultKind Kind { get; set; }

        public string Description { get; set; }

        public string ContentsRegex { get; set; }

        public string FileNameDenyRegex { get; set; }

        public string FileNameAllowRegex { get; set; }

        /// <summary>
        /// Gets or sets a value indicating the length of a typical match.
        /// If this value is non-zero, the scanner will first attempt
        /// to detect a base64-encoded value that decodes to this length.
        /// On detection, it will next decode this value and provide the
        /// decoded string to the match expression. No base64-decoding
        /// occurs when this property is 0 or less.
        /// </summary>
        public int MatchLengthToDecode { get; set; }

        public Dictionary<string, string> Properties { get; set; }

        public Dictionary<string, string> MessageArguments { get; set; }

        public IList<string> Notes { get; set; }

        public IDictionary<string, SimpleFix> Fixes { get; set; }

        public Dictionary<string, int> ArgumentNameToIndexMap { get; set; }

        public bool IsValidatorEnabled { get; set; } = true;

        public string MessageId { get; set; } = "Default";
    }
}
