// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommandLine;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    [Verb("import-analyze", HelpText = "Export rules metadata to a markdown file.")]
    internal class ImportAndAnalyzeOptions : AnalyzeOptions
    {
        [Option(
            "host",
            HelpText = "The database host from which we will retrieve data to scan. " +
                       "Create AppClientId, AppSecrent, and AuthorityId as environment variables.",
            Required = true)]
        public string Host { get; set; }

        [Option(
            "database",
            HelpText = "The database from which we will retrieve content to scan.",
            Required = true)]
        public string Database { get; set; }

        [Option(
            "query",
            HelpText = "The query that will be used to retrieve content to scan.",
            Required = true)]
        public string Query { get; set; }

        [Option(
            "retain-downloaded-content",
            HelpText = "If set to true, the downloaded files won't be deleted.")]
        public bool RetainDownloadedContent { get; set; }
    }
}
