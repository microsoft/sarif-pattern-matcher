// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;

using CommandLine;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    /// <summary>
    /// export-search-definitions is a command line option that accepts three parameters: input, output, and type.
    /// This command transforms the input file in a search definitionformat, which is used in our plugins.
    /// </summary>
    [Verb("export-search-definitions", HelpText = "Export search definitions file from specific formats.")]
    internal class ExportSearchDefinitionsOptions
    {
        [Value(
            0,
            HelpText = "Output path for exported search definitions json.",
            Required = true)]
        public string OutputFilePath { get; set; }

        [Option(
            "input",
            HelpText = "A path to a file that you want to export as search definition.",
            Required = true)]
        public string InputFilePath { get; set; }

        [Option(
            "type",
            HelpText = "Type of the input file (BannedApi or Sal).",
            Required = true)]
        public string FileType { get; set; }

        public bool Validate()
        {
            return File.Exists(InputFilePath);
        }
    }
}
