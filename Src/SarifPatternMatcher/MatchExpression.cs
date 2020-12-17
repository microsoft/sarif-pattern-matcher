// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher
{
    public class MatchExpression
    {
        public string SubId { get; set; }

        public string NameRegex { get; set; }

        public FailureLevel Level { get; set; }

        public string ContentsRegex { get; set; }

        /// <summary>
        /// Gets or sets a value indicating the length of a typical match.
        /// If this value is non-zero, the scanner will first attempt
        /// to detect a base64-encoded value that decodes to this length.
        /// On detection, it will next decode this value and provide the
        /// decoded string to the match expression. No base64-decoding
        /// occurs when this property is 0 or less.
        /// </summary>
        public int MatchLengthToDecode { get; set; }

        public Dictionary<string, string> MessageArguments { get; set; }

        public IList<string> Notes { get; set; }

        public IDictionary<string, SimpleFix> Fixes { get; set; }
    }
}
