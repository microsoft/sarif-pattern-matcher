// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using BenchmarkDotNet.Running;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Benchmark.Benchmarks;

namespace Sarif.PatternMatcher.Benchmark
{
    internal static class Program
    {
        static void Main(string[] args)
        {
            BenchmarkRunner.Run<AnalyzeCommandBenchmarks>();
        }
    }
}
