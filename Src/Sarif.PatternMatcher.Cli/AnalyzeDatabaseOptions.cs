// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli.Enums;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    [Verb("analyze-database", HelpText = "Analyze a database.")]
    internal class AnalyzeDatabaseOptions : AnalyzeOptions
    {
        [Option(
            "connection",
            Required = true,
            HelpText = "Connection string to data source (Kusto).")]
        public string Connection { get; internal set; }

        [Option(
            "data-type",
            Required = true,
            HelpText = "Connection type for the data. Valid inputs: Kusto, SqlLite.")]
        public ConnectionType ConnectionType { get; internal set; }

        [Option(
            "target",
            Required = true,
            HelpText = "Data target to analyze against. For example a Kusto query, or SqlLite query.")]
        public string Target { get; internal set; }

        [Option(
            "batch-size",
            Default = 0,
            HelpText = "Number of rows of data to process per thread.")]
        public int BatchSize { get; internal set; }

        [Option(
            "identity",
            Required = true,
            HelpText = "Column name from your target data query/table that can ordered by for batch processing.")]
        public string IdentityColumn { get; internal set; }
    }
}
