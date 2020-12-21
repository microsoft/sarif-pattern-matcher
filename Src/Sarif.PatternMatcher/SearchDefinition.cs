// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class SearchDefinition
    {
        public Dictionary<string, string> Strings { get; set; }

        public string Id { get; set; }

        public string Name { get; set; }

        public string Description { get; set; }

        public string Message { get; set; }

        public FailureLevel Level { get; set; }

        public string FileNameDenyRegex { get; set; }

        public string FileNameAllowRegex { get; set; }

        public List<MatchExpression> MatchExpressions { get; set; }
    }
}
