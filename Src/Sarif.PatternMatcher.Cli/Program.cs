// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Text;

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            return Parser.Default.ParseArguments<
                AnalyzeOptions,
                AnalyzeDatabaseOptions,
                ExportRulesMetatadaOptions,
                ExportSearchDefinitionsOptions,
                ImportAndAnalyzeOptions,
                ValidateOptions>(args)
              .MapResult(
                (AnalyzeDatabaseOptions options) => new AnalyzeDatabaseCommand().Run(options),
                (ImportAndAnalyzeOptions options) => new ImportAndAnalyzeCommand().Run(options),
                (AnalyzeOptions options) => new AnalyzeCommand().Run(options),
                (ExportRulesMetatadaOptions options) => new ExportRulesMetatadaCommand().Run(options),
                (ExportSearchDefinitionsOptions options) => new ExportSearchDefinitionsCommand().Run(options),
                (ValidateOptions options) => new ValidateCommand().Run(options),
                _ => CommandBase.FAILURE);
        }
    }
}
