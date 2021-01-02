// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    [Verb("analyze")]
    public class AnalyzeOptions : AnalyzeOptionsBase
    {
        [Option(
            'd',
            "search-definitions",
            HelpText = "A path to a file containing one or more search definitions to drive analysis.")]
        public IEnumerable<string> SearchDefinitionsPaths { get; internal set; }

        [Option(
            "dynamic-validation",
            HelpText = "Enable dynamic validations, if any (may compromise " +
                       "performance and/or result in calls across the network).")]
        public bool DynamicValidation { get; internal set; }
    }
}
