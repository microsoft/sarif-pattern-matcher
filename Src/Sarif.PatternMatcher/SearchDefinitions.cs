// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class SearchDefinitions
    {
        public string SharedStringsFileName { get; set; }

        public string ValidatorsAssemblyName { get; set; }

        public string ExtensionName { get; set; }

        public Guid Guid { get; set; }

        public List<SearchDefinition> Definitions { get; set; }
    }
}
