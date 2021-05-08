// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Threading.Channels;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli.DatabaseReaders
{
    internal abstract class BaseReader
    {
        protected readonly Channel<string> contentChannel;
        protected readonly ConcurrentDictionary<string, string> content;

        protected BaseReader(Channel<string> contentChannel, ConcurrentDictionary<string, string> content)
        {
            this.content = content;
            this.contentChannel = contentChannel;
        }

        protected void ReadAll(IDataReader reader, string identity)
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
    }
}
