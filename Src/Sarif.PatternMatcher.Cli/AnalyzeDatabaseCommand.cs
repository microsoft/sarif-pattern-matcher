// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Text;
using System.Threading.Channels;
using System.Threading.Tasks;

using Kusto.Data.Common;
using Kusto.Data.Net.Client;

using Microsoft.CodeAnalysis.Sarif.Driver;
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
                options.Threads = options.Threads > 0 ? options.Threads : Environment.ProcessorCount * 4;
                dynamicValidation = options.DynamicValidation;

                contentChannel = Channel.CreateUnbounded<string>();

                AggregatingLogger aggregatingLogger = InitializeLogger(options);

                var sarifLogger = new SarifLogger(
                    options.OutputFilePath,
                    options.ConvertToLogFilePersistenceOptions(),
                    dataToInsert: options.DataToInsert.ToFlags(),
                    dataToRemove: options.DataToRemove.ToFlags(),
                    tool: MakeTool(),
                    levels: options.Level,
                    kinds: options.Kind);
                aggregatingLogger.Loggers.Add(sarifLogger);

                aggregatingLogger.AnalysisStarted();
                ISet<Skimmer<AnalyzeContext>> skimmers = AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(FileSystem, options.SearchDefinitionsPaths);

                var workers = new Task<bool>[options.Threads];

                for (int i = 0; i < options.Threads; i++)
                {
                    workers[i] = AnalyzeTargetAsync(aggregatingLogger, skimmers);
                }

                switch (options.ConnectionType)
                {
                    case Enums.ConnectionType.Kusto:
                    {
                        QueryKusto(options);
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

        private static int GetIndex(IDataReader dataReader, Dictionary<string, int> dataReaderIndex, string key)
        {
            int index;
            try
            {
                if (!dataReaderIndex.TryGetValue(key, out index))
                {
                    dataReaderIndex[key] = index = dataReader.GetOrdinal(key);
                }
            }
            catch (ArgumentException)
            {
                // When we don't find, let's set to -1.
                dataReaderIndex[key] = index = -1;
            }

            return index;
        }

        private void QueryKusto(AnalyzeDatabaseOptions options)
        {
            long queryRowCount;
            string query = options.Target;
            string identityColumn = options.IdentityColumn;
            string countQuery = $"{query} | count";

            int batchSize = (options.BatchSize > 0) ? options.BatchSize : DefaultBatchSize;
            string tableName = query.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries)[0].Trim();

            // Get the total number of rows for the target query
            using (ICslQueryProvider provider = KustoClientFactory.CreateCslQueryProvider(options.Connection))
            {
                using (IDataReader reader = provider.ExecuteQuery(countQuery))
                {
                    reader.Read();
                    queryRowCount = reader.GetInt64(0);
                }
            }

            double steps = Math.Ceiling((float)queryRowCount / batchSize);
            var batchQueries = new List<string>((int)steps);
            for (int i = 0; i < steps; i++)
            {
                string batchStepQuery;
                if (i == 0)
                {
                    // The current logic for the Kusto query for a single batch is as follows. This happens on the Kusto cluster as part of the query.
                    // 1. Execute and cache the original query.
                    // 2. Make a first result set which is the results of the original query filtered to only the identity column, ordered by the identity column, and has an additional column added which is the row number.
                    // 3. Filter the first result set where row number is between the current batch row number range.
                    // 4. Make a second result set that contains the entire results of the original query.
                    // 5. Join the first and second result sets together on the identity column.
                    batchStepQuery = $"set notruncation;let mainQuery=materialize({query}); mainQuery | project {identityColumn} | order by {identityColumn} asc | extend BatchingRowNum=row_number() | where BatchingRowNum <= {batchSize} | project-away BatchingRowNum | join (mainQuery) on {identityColumn}";
                }
                else
                {
                    batchStepQuery = $"set notruncation;let mainQuery=materialize({query}); mainQuery | project {identityColumn} | order by {identityColumn} asc | extend BatchingRowNum=row_number() | where BatchingRowNum > {i * batchSize} and BatchingRowNum <= {(i + 1) * batchSize} | project-away BatchingRowNum | join (mainQuery) on {identityColumn}";
                }

                batchQueries.Add(batchStepQuery);
            }

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = options.Threads,
            };

            Parallel.ForEach(batchQueries, parallelOptions, (stepQuery) => ProcessBatch(options, stepQuery));

            contentChannel.Writer.Complete();
        }

        private void ProcessBatch(AnalyzeDatabaseOptions options, string stepQuery)
        {
            // Discard any empty queries
            if (string.IsNullOrWhiteSpace(stepQuery))
            {
                return;
            }

            // Run actual Kusto query
            using (ICslQueryProvider provider = KustoClientFactory.CreateCslQueryProvider(options.Connection))
            {
                IDataReader reader = null;

                try
                {
                    reader = provider.ExecuteQuery(stepQuery);
                    ReadAll(reader, options.IdentityColumn);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
                finally
                {
                    reader?.Dispose();
                }
            }
        }

        private void ReadAll(IDataReader reader, string identity)
        {
            var dataReaderIndex = new Dictionary<string, int>();

            while (reader.Read())
            {
                object[] values = new object[reader.FieldCount];
                int num_fields = reader.GetValues(values);

                string indexValue = null;
                if (GetIndex(reader, dataReaderIndex, identity) != -1)
                {
                    indexValue = reader.GetValue(GetIndex(reader, dataReaderIndex, identity)).ToString();
                }

                for (int i = 0; i < num_fields; i++)
                {
                    if (!reader.IsDBNull(i))
                    {
                        if (!(values[i] is string columnData))
                        {
                            continue;
                        }

                        string columnName = reader.GetName(i);
                        string contentName = $"{indexValue}_{columnName}";
                        content[contentName] = columnData;
                        contentChannel.Writer.TryWrite(contentName);
                    }
                }
            }
        }

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
                            var context = new AnalyzeContext
                            {
                                Logger = logger,
                                FileContents = contentData,
                                DynamicValidation = dynamicValidation,
                                TargetUri = new Uri(contentName, UriKind.RelativeOrAbsolute),
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

            if (!analyzeOptions.Quiet)
            {
                var consoleLogger = new ConsoleLogger(analyzeOptions.Quiet, tool.Driver.Name, analyzeOptions.Level, analyzeOptions.Kind);
                logger.Loggers.Add(consoleLogger);
            }

            return logger;
        }
    }
}
