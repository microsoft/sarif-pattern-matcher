// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Channels;
using System.Threading.Tasks;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli.DatabaseReaders;
using Microsoft.CodeAnalysis.Sarif.Writers;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal class AnalyzeDatabaseCommand : CommandBase
    {
        private const int DefaultBatchSize = 10000;
        private readonly HashSet<string> disabledSkimmers;
        private readonly ConcurrentDictionary<string, string> content;
        private bool dynamicValidation;
        private Channel<string> contentChannel;

        public AnalyzeDatabaseCommand()
        {
            disabledSkimmers = new HashSet<string>();
            content = new ConcurrentDictionary<string, string>();
        }

        public int Run(AnalyzeDatabaseOptions options)
        {
            try
            {
                options.BatchSize = (options.BatchSize > 0) ? options.BatchSize : DefaultBatchSize;
                options.Threads = options.Threads > 0 ? options.Threads : Environment.ProcessorCount * 4;
                dynamicValidation = options.DynamicValidation;

                contentChannel = Channel.CreateUnbounded<string>();

                AggregatingLogger aggregatingLogger = InitializeLogger(options);

                var run = new Run { Tool = MakeTool() };

                var sarifLogger = new SarifLogger(
                    options.OutputFilePath,
                    options.OutputFileOptions.ToFlags(),
                    dataToInsert: options.DataToInsert.ToFlags(),
                    dataToRemove: options.DataToRemove.ToFlags(),
                    run: run,
                    levels: options.FailureLevels,
                    kinds: options.ResultKinds);
                aggregatingLogger.Loggers.Add(sarifLogger);

                aggregatingLogger.AnalysisStarted();
                ISet<Skimmer<AnalyzeContext>> skimmers = AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(FileSystem, options.SearchDefinitionsPaths, run.Tool);

                var workers = new Task<bool>[options.Threads];

                for (int i = 0; i < options.Threads; i++)
                {
                    workers[i] = AnalyzeTargetAsync(aggregatingLogger, skimmers);
                }

                switch (options.ConnectionType)
                {
                    case Enums.ConnectionType.Kusto:
                    {
                        var reader = new KustoDatabaseReader(contentChannel, content);
                        reader.Query(options);
                        break;
                    }

                    case Enums.ConnectionType.SqlLite:
                    {
                        var reader = new SqlLiteDatabaseReader(contentChannel, content);
                        reader.Query(options);
                        break;
                    }

                    default:
                    {
                        throw new NotImplementedException();
                    }
                }

                Task.WhenAll(workers).Wait();

                aggregatingLogger.AnalysisStopped(RuntimeConditions.None);
                aggregatingLogger?.Dispose();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return FAILURE;
            }

            return SUCCESS;
        }

        private static Tool MakeTool() => new Tool
        {
            Driver = new ToolComponent
            {
                Name = "Live Secrets Detection",
            },
        };

        private async Task<bool> AnalyzeTargetAsync(IAnalysisLogger logger, IEnumerable<Skimmer<AnalyzeContext>> skimmers)
        {
            ChannelReader<string> reader = contentChannel.Reader;

            // Wait until there is work or the channel is closed.
            while (await reader.WaitToReadAsync())
            {
                // Loop while there is work to do.
                while (reader.TryRead(out string contentName))
                {
                    if (content.TryRemove(contentName, out string contentData))
                    {
                        try
                        {
                            var target = new EnumeratedArtifact(FileSystem)
                            {
                                Uri = new Uri(contentName, UriKind.RelativeOrAbsolute),
                                Contents = contentData,
                            };

                            var context = new AnalyzeContext
                            {
                                Logger = logger,
                                CurrentTarget = target,
                                DynamicValidation = dynamicValidation,
                            };

                            using (context)
                            {
                                AnalyzeCommand.AnalyzeTargetHelper(context, skimmers, disabledSkimmers);
                            }
                        }
                        catch (Exception e)
                        {
                            Console.Error.WriteLine(e.Message);
                        }
                    }
                }
            }

            return true;
        }

        private AggregatingLogger InitializeLogger(AnalyzeOptionsBase analyzeOptions)
        {
            Tool tool = MakeTool();
            var logger = new AggregatingLogger();

            if (!(analyzeOptions.Quiet == true))
            {
                var consoleLogger = new ConsoleLogger(quietConsole: false, tool.Driver.Name, analyzeOptions.FailureLevels, analyzeOptions.ResultKinds);
                logger.Loggers.Add(consoleLogger);
            }

            return logger;
        }
    }
}
