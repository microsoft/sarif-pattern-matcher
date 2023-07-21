// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Text;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

using Microsoft.RE2.Managed;

using Sarif.PatternMatcher.Benchmark;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Benchmark.Benchmarks
{
    public class RegexBenchmarks : BenchmarksBase
    {
        public int Run(RegexOptions _)
        {
            if (!Debugger.IsAttached)
            {
                BenchmarkRunner.Run<RegexBenchmarks>();
            }
            else
            {
                new RegexBenchmarks()
                {
                    findAllMatches = true,
                    targetContents = GenerateScanTarget(1)
                }.Regex_IndexOf();
            }
            return 0;
        }

        [Params(1)]
        public int scanTargetSizeInKilobytes;

        [Params(true, false)]
        public bool findAllMatches;

        private string targetContents;

        [GlobalSetup]
        public void Setup()
        {
            targetContents = GenerateScanTarget(scanTargetSizeInKilobytes);
        }

        private const string s_signature = "\\+ASt";

        //[Benchmark]
        public void Regex_CachedDotNetRegex()
        {
            int count = 0;
            if (findAllMatches)
            {
                foreach (FlexMatch match in CachedDotNetRegex.Instance.Matches(s_signature, targetContents))
                {
                    count++;
                }
            }
            else
            {
                DotNetRegex.Instance.IsMatch(targetContents, s_signature);
            }
        }

        //[Benchmark]
        public void Regex_DotNetRegex()
        {
            int count = 0;
            if (findAllMatches)
            {
                foreach (FlexMatch match in DotNetRegex.Instance.Matches(s_signature, targetContents))
                {
                    count++;
                }
            }
            else
            {
                DotNetRegex.Instance.IsMatch(targetContents, s_signature);
            }
        }

        [Benchmark]
        public void Regex_IndexOf()
        {
            int index = 0;
            if (findAllMatches)
            {
                while (index >= 0 && index < targetContents.Length)
                {
                    index = targetContents.IndexOf(s_signature, index + s_signature.Length);
                }
            }
            else
            {
                targetContents.IndexOf(s_signature);
            }
        }

        [Benchmark]
        public void Regex_RE2Regex()
        {
            int count = 0;
            if (findAllMatches)
            {
                foreach (FlexMatch match in RE2Regex.Instance.Matches(s_signature, targetContents))
                {
                    count++;
                }
            }
            else
            {
                DotNetRegex.Instance.IsMatch(targetContents, s_signature);
            }
        }

        [Benchmark]
        public void Regex_IronRE2()
        {
            int count = 0;
            if (findAllMatches)
            {
                foreach (FlexMatch match in IronRE2Regex.Instance.Matches(s_signature, targetContents))
                {
                    count++;
                }
            }
            else
            {
                DotNetRegex.Instance.IsMatch(targetContents, s_signature);
            }
        }

        private static string GenerateScanTarget(int sizeInMegabytes)
        {
            var sb = new StringBuilder();

            int size = sizeInMegabytes * 1024;

            while (sb.Length < size)
            {
                sb.Append($"{Guid.NewGuid()} {s_signature}");
            }

            return sb.ToString();
        }
    }
}
