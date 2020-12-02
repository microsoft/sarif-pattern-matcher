// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher
{
    public class SearchDefinition
    {
        public string Id { get; set; }

        public string Name { get; set; }

        public string Description { get; set; }

        public string Message { get; set; }

        public FailureLevel Level { get; set; }

        public string DefaultNameRegex { get; set; }

        public List<MatchExpression> MatchExpressions { get; set; }
    }
}
