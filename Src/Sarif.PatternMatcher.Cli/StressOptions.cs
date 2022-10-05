// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    [Verb("stress", HelpText = "Run various stress scenarios.")]
    internal class StressOptions : SingleFileOptionsBase
    {
        [Value(
            0,
            HelpText = "A naive performance or stress scenario name (currently Statelessness or RE2Timing).",
            Required = true)]
        public StressScenario Scenario { get; set; }

        [Option(
            "iterations",
            HelpText = "The # of iterations to run of the specified scenario.",
            Default = 1
            )]
        public int Iterations { get; set; }

        [Option(
            'd',
            "search-definitions",
            Separator = ';',
            Required = true,
            HelpText = "A path to a file containing one or more search definitions to drive analysis.")]
        public IEnumerable<string> SearchDefinitionsPaths { get; set; }
    }

    public enum StressScenario
    {
        Statelessness = 0,
        RE2Timing,
        FileSizeVsTime,
    }
}
