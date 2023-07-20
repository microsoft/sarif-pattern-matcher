// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using BenchmarkDotNet.Running;

using CommandLine;

using IronRe2;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Benchmark.Benchmarks;

namespace Sarif.PatternMatcher.Benchmark
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            return Parser.Default.ParseArguments<
                SimpleOptions,
                LargeFileOptions,
                SniffAdoPatOptions,
                SniffFullOptions,
                SniffSingleLiteralOptions,
                RegexOptions>(args)
              .MapResult(
                (SimpleOptions options) => new SimpleFileBenchmarks().Run(options),
                (LargeFileOptions options) => new LargeFileBenchmarks().Run(options),
                (SniffAdoPatOptions options) => new SniffAdoPatBenchmark(options).Run(),
                (SniffFullOptions options) => new SniffFullBenchmark(options).Run(),
                (SniffSingleLiteralOptions options) => new SniffSingleLiteralBenchmark(options).Run(),
                (RegexOptions options) => new RegexBenchmarks().Run(options),
                _ => 1);
        }
    }
}
