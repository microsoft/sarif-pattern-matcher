// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using CommandLine;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    [Verb("export-rules", HelpText = "Export rules metadata to a markdown file.")]
    internal class ExportRulesMetatadaOptions
    {
        [Value(
            0,
            HelpText = "Output path for exported analysis options. Use .md to produce a markdow rule descriptor file.",
            Required = true)]
        public string OutputFilePath { get; set; }

        [Option(
            'd',
            "search-definitions",
            Separator = ';',
            HelpText = "A path to a file containing one or more search definitions to drive analysis.")]
        public IEnumerable<string> SearchDefinitionsPaths { get; set; }
    }
}
