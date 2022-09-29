// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    [Verb("timing", HelpText = "Run timing tests")]
    internal class TimingOptions : CommonOptionsBase
    {
        [Value(0,
               HelpText = "One or more specifiers to a file, directory, or filter pattern that resolves to one or more binaries to analyze.")]
        public IEnumerable<string> TargetFileSpecifiers { get; set; }

        [Option(
            'd',
            "search-definitions",
            Separator = ';',
            Required = true,
            HelpText = "A path to a file containing one or more search definitions to drive analysis.")]
        public IEnumerable<string> SearchDefinitionsPaths { get; set; }

        public long MaxMemoryInKilobytes { get; internal set; }
    }
}
