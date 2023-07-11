// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Threading.Channels;
using System.Threading.Tasks;

using Kusto.Data.Common;
using Kusto.Data.Net.Client;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli.DatabaseReaders
{
    internal class KustoDatabaseReader : BaseReader, IDatabaseReader
    {
        public KustoDatabaseReader(Channel<string> contentChannel, ConcurrentDictionary<string, string> content)
            : base(contentChannel, content)
        {
        }

        public void Query(AnalyzeDatabaseOptions options)
        {
            long queryRowCount;
            string query = options.Target;
            int batchSize = options.BatchSize;
            string identityColumn = options.IdentityColumn;
            string countQuery = $"{query} | count";

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

            Parallel.ForEach(batchQueries, parallelOptions, (stepQuery) => ProcessBatch(options.Connection, stepQuery, identityColumn));

            contentChannel.Writer.Complete();
        }

        public void ProcessBatch(string connection, string stepQuery, string identity)
        {
            // Discard any empty queries
            if (string.IsNullOrWhiteSpace(stepQuery))
            {
                return;
            }

            // Run actual Kusto query
            using (ICslQueryProvider provider = KustoClientFactory.CreateCslQueryProvider(connection))
            {
                IDataReader reader = null;

                try
                {
                    reader = provider.ExecuteQuery(stepQuery);
                    ReadAll(reader, identity);
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
    }
}
