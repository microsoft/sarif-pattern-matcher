// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommandLine;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    [Verb("import", HelpText = "Export rules metadata to a markdown file.")]
    internal class ImportAndAnalyzeOptions : AnalyzeOptions
    {
        [Option(
            "temp-folder",
            HelpText = "A temp folder path to save all files.")]
        public string TempFolder { get; set; }

        [Option(
            "host-address",
            HelpText = "The host address from where we will fetch the data.",
            Required = true)]
        public string HostAddress { get; set; }

        [Option(
            "database",
            HelpText = "The database that we will connect.",
            Required = true)]
        public string Database { get; set; }

        [Option(
            "query",
            HelpText = "The query that will be used to generate the SARIF.",
            Required = true)]
        public string Query { get; set; }

        public bool Validate()
        {
            if (string.IsNullOrEmpty(TempFolder))
            {
                return false;
            }

            return true;
        }
    }
}
