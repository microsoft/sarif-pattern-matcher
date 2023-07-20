// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

using Microsoft.RE2.Managed;

using Sarif.PatternMatcher.Benchmark;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Benchmark.Benchmarks
{
    public class SniffAdoPatBenchmark : SniffBenchmark
    {
        //BenchmarkDotNet=v0.12.1, OS=Windows 10.0.22621
        //Intel Xeon W-2133 CPU 3.60GHz, 1 CPU, 12 logical and 6 physical cores
        //  [Host]     : .NET Framework 4.8 (4.8.9166.0), X64 RyuJIT
        //  DefaultJob : .NET Framework 4.8 (4.8.9166.0), X64 RyuJIT

        // Signature: "[2-7a-z]{52}",

        //|         Method | FindAllMatches | UseSyntheticContent |       Mean |    Error |   StdDev |
        //|--------------- |--------------- |-------------------- |-----------:|---------:|---------:|
        //|        IndexOf |          False |               False |   665.2 ms | 13.01 ms | 23.13 ms |
        //| RE2RegexEngine |          False |               False | 3,038.7 ms | 59.38 ms | 66.00 ms |

        public SniffAdoPatBenchmark() : this(null)
        {
        }

        public SniffAdoPatBenchmark(SniffAdoPatOptions options) : base(options)
        {
        }

        protected override void InitializeSignatures()
        {
            RunIndexOfAdoPat = true;

            Signatures = new string[0];

            RegexSignatures = new[] {
                "[2-7a-z]{52}",
            };
        }
    }
}
