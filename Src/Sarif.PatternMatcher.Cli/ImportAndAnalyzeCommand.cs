// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.Multitool;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal class ImportAndAnalyzeCommand : CommandBase
    {
        public int Run(ImportAndAnalyzeOptions options)
        {
            string sarifPath = string.Empty;

            try
            {
                if (!options.Validate())
                {
                    return FAILURE;
                }

                if (ImportDataFromKusto(options, out sarifPath) == FAILURE)
                {
                    return FAILURE;
                }

                if (SaveResults(options, sarifPath) == FAILURE)
                {
                    return FAILURE;
                }

                return new AnalyzeCommand().Run(options);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return FAILURE;
            }
            finally
            {
                if (FileSystem.FileExists(sarifPath))
                {
                    FileSystem.FileDelete(sarifPath);
                }

                if (FileSystem.DirectoryExists(options.TempFolder))
                {
                    FileSystem.DirectoryDelete(options.TempFolder);
                }
            }
        }

        private static int ImportDataFromKusto(ImportAndAnalyzeOptions options, out string sarifPath)
        {
            sarifPath = Path.Combine(options.TempFolder, "kusto.sarif");

            var kustoOptions = new KustoOptions
            {
                HostAddress = options.HostAddress,
                Database = options.Database,
                Query = options.Query,
                OutputFilePath = sarifPath,
            };

            var kustoCommand = new KustoCommand();
            int kustoResult = kustoCommand.Run(kustoOptions);
            return kustoResult != 0 ? FAILURE : SUCCESS;
        }

        private int SaveResults(ImportAndAnalyzeOptions options, string sarifPath)
        {
            var sarifLog = SarifLog.Load(sarifPath);

            if (FileSystem.FileExists(sarifPath))
            {
                FileSystem.FileDelete(sarifPath);
            }

            if (sarifLog == null || sarifLog.Runs?.Count == 0)
            {
                return FAILURE;
            }

            foreach (Run run in sarifLog.Runs)
            {
                if (run.Results != null)
                {
                    foreach (Result result in run.Results)
                    {
                        foreach (Location location in result.Locations)
                        {
                            if (!string.IsNullOrEmpty(location.PhysicalLocation?.ContextRegion?.Snippet?.Text))
                            {
                                FileSystem.FileWriteAllText(Path.Combine(options.TempFolder, $"{Guid.NewGuid()}.txt"), location.PhysicalLocation?.ContextRegion?.Snippet?.Text);
                            }
                        }
                    }
                }
            }

            return SUCCESS;
        }
    }
}
