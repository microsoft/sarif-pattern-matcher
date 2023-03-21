// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.Multitool;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal class ImportAndAnalyzeCommand : CommandBase
    {
        private const string FolderName = "SarifPatternMatcherCli\\";
        private static readonly List<string> Files = new List<string>();

        public int Run(ImportAndAnalyzeOptions options)
        {
            string basePath = Path.Combine(Path.GetTempPath(), FolderName);

            try
            {
                if (!FileSystem.DirectoryExists(basePath))
                {
                    FileSystem.DirectoryCreateDirectory(basePath);
                }

                string sarifPath;
                if (ImportDataFromKusto(options, basePath, out sarifPath) == FAILURE)
                {
                    return FAILURE;
                }

                if (SaveResults(sarifPath, basePath) == FAILURE)
                {
                    return FAILURE;
                }

                // This is needed to scan the temp folder.
                options.TargetFileSpecifiers = new List<string> { basePath };
                options.Recurse = true;
                return new AnalyzeCommand().Run(options);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return FAILURE;
            }
            finally
            {
                if (!options.RetainDownloadedContent)
                {
                    foreach (string file in Files)
                    {
                        if (FileSystem.FileExists(file))
                        {
                            FileSystem.FileDelete(file);
                        }
                    }
                }
            }
        }

        private static int ImportDataFromKusto(ImportAndAnalyzeOptions options, string basePath, out string sarifPath)
        {
            sarifPath = Path.Combine(basePath, "kusto.sarif");
            Files.Add(sarifPath);

            var kustoOptions = new KustoOptions
            {
                HostAddress = options.Host,
                Database = options.Database,
                Query = options.Query,
                OutputFilePath = sarifPath,
            };

            var kustoCommand = new KustoCommand();
            int kustoResult = kustoCommand.Run(kustoOptions);
            return kustoResult != 0 ? FAILURE : SUCCESS;
        }

        private int SaveResults(string sarifPath, string basePath)
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
                                string path = Path.Combine(basePath, $"{Guid.NewGuid()}.txt");
                                FileSystem.FileWriteAllText(path, location.PhysicalLocation?.ContextRegion?.Snippet?.Text);
                                Files.Add(path);
                            }
                        }
                    }
                }
            }

            return SUCCESS;
        }
    }
}
