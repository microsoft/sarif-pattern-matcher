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

        public string Message { get; set; }

        public string NameRegex { get; set; }

        public FailureLevel Level { get; set; }

        public string ContentsRegex { get; set; }

        public int Base64DecodedContentLength { get; set; }

        public Dictionary<string, string> MessageArguments { get; set; }

        public IList<string> Notes { get; set; }

        public IDictionary<string, SimpleFix> Fixes { get; set; }
    }
}
