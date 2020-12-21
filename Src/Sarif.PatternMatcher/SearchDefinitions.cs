// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class SearchDefinitions
    {
        public string ValidatorsAssemblyName { get; set; }

        public Dictionary<string, string> Strings { get; set; }

        public List<SearchDefinition> Definitions { get; set; }
    }
}
