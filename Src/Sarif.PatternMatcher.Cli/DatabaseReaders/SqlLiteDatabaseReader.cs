// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Threading.Channels;
using System.Threading.Tasks;

using Microsoft.Data.Sqlite;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli.DatabaseReaders
{
    internal class SqlLiteDatabaseReader : BaseReader, IDatabaseReader
    {
        public SqlLiteDatabaseReader(Channel<string> contentChannel, ConcurrentDictionary<string, string> content)
            : base(contentChannel, content)
        {
        }

        public void ProcessBatch(string connection, string stepQuery, string identity)
        {
            // Discard any empty queries
            if (string.IsNullOrWhiteSpace(stepQuery))
            {
                return;
            }

            using (var conn = new SqliteConnection(connection))
            {
                IDataReader reader = null;

                try
                {
                    conn.Open();
                    using SqliteCommand cmd = conn.CreateCommand();
                    cmd.CommandText = stepQuery;
                    reader = cmd.ExecuteReader();
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

        public void Query(AnalyzeDatabaseOptions options)
        {
            long queryRowCount = 0;
            string query = options.Target;
            int batchSize = options.BatchSize;
            string identityColumn = options.IdentityColumn;
            string countQuery = $"SELECT COUNT() FROM ({query})";

            using (var connection = new SqliteConnection(options.Connection))
            {
                connection.Open();
                using SqliteCommand cmd = connection.CreateCommand();
                cmd.CommandText = countQuery;
                using SqliteDataReader reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    queryRowCount = reader.GetInt64(0);
                }
            }

            double steps = Math.Ceiling((float)queryRowCount / batchSize);
            var batchQueries = new List<string>((int)steps);
            long skip = 0;
            for (int i = 0; i < steps; i++)
            {
                string batchStepQuery = $"{query} ORDER BY {identityColumn} LIMIT {skip}, {options.BatchSize}";
                skip += batchSize;

                batchQueries.Add(batchStepQuery);
            }

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = options.Threads,
            };

            Parallel.ForEach(batchQueries, parallelOptions, (stepQuery) => ProcessBatch(options.Connection, stepQuery, identityColumn));

            contentChannel.Writer.Complete();
        }
    }
}
