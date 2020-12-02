// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher
{
    [Verb("analyze")]
    public class AnalyzeOptions : MultithreadedAnalyzeOptionsBase
    {
        [Option(
            'd',
            "search-definitions",
            HelpText = "A path to a file containing one or more search definitions to drive analysis.")]
        public IEnumerable<string> SearchDefinitionsPaths { get; internal set; }
    }
}
