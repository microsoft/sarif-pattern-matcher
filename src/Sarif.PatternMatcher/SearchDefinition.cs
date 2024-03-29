﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class SearchDefinition
    {
        public string ExtensionName { get; set; }

        public Dictionary<string, string> SharedStrings { get; set; }

        public string Id { get; set; }

        public string Name { get; set; }

        public string HelpUri { get; set; }

        public string Message { get; set; }

        public ResultKind Kind { get; set; }

        public RuleEnabledState RuleEnabledState { get; set; }

        public FailureLevel Level { get; set; }

        public string Description { get; set; }

        public string FileNameDenyRegex { get; set; }

        public string FileNameAllowRegex { get; set; }

        public List<MatchExpression> MatchExpressions { get; set; }

#if DEBUG

        public override string ToString()
        {
            return $"{Id}.{Name}:{Level}";
        }

#endif
    }
}
