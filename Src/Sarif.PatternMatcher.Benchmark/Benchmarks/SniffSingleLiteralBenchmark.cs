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
    public class SniffSingleLiteralBenchmark : SniffBenchmark
    {
        //BenchmarkDotNet=v0.12.1, OS=Windows 10.0.22621
        //Intel Xeon W-2133 CPU 3.60GHz, 1 CPU, 12 logical and 6 physical cores
        //  [Host]     : .NET Framework 4.8 (4.8.9166.0), X64 RyuJIT
        //  DefaultJob : .NET Framework 4.8 (4.8.9166.0), X64 RyuJIT

        // Signature: "\\.core\\.windows\\.net",

        //|         Method | FindAllMatches | UseSyntheticContent |        Mean |     Error |    StdDev |
        //|--------------- |--------------- |-------------------- |------------:|----------:|----------:|
        //|        IndexOf |          False |               False |    65.66 ms |  1.297 ms |  2.929 ms |
        //| RE2RegexEngine |          False |               False | 1,316.35 ms | 25.923 ms | 42.592 ms |


        // Signature: "aio_",

        //|         Method | FindAllMatches | UseSyntheticContent |        Mean |     Error |    StdDev |
        //|--------------- |--------------- |-------------------- |------------:|----------:|----------:|
        //|        IndexOf |          False |               False |    70.90 ms |  1.405 ms |  3.870 ms |
        //| RE2RegexEngine |          False |               False | 1,351.02 ms | 26.596 ms | 38.143 ms |

        public SniffSingleLiteralBenchmark() : this(null)
        {
        }

        public SniffSingleLiteralBenchmark(SniffSingleLiteralOptions options) : base(options)
        {
        }

        protected override void InitializeSignatures()
        {
            RunIndexOfAdoPat = false;

            Signatures = new[] {
                ".core.windows.net",
            };

            RegexSignatures = new[] {
                "\\.core\\.windows\\.net",
            };
        }
    }
}
