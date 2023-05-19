// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli.Enums;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    [Verb("generate-synth-data", HelpText = "Generate a synthetic dataset from plugins.")]
    internal class GenerateSynthDataOptions: AnalyzeOptionsBase
    {
        [Option(
            "min-strings-perfile",
            Default = 100,
            HelpText = "Minimum number of strings to be generated per file.")]
        public int MinStringsPerFile { get; set; }

        [Option(
            "max-strings-perfile",
            Default = 1000000000,
            HelpText = "Maximum number of strings to be generated per file.")]
        public int MaxStringsPerFile { get; set; }
    }
}
