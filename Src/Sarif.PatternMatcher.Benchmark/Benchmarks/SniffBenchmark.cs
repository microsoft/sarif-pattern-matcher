// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

using Microsoft.RE2.Managed;

using Sarif.PatternMatcher.Benchmark;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Benchmark.Benchmarks
{
    public abstract class SniffBenchmark : BenchmarksBase
    {
        private readonly Lazy<string> _regexSignature;
        protected const string SyntheticFileName = "synthetic.txt";

        protected string TargetsDirectory { get => @"D:\ConfigChange\src\Governance"; }
        protected Dictionary<string, string> TargetContents;

        protected string[] Signatures { get; set; }
        protected string[] RegexSignatures { get; set; }
        protected string RegexSignature { get => _regexSignature.Value; }

        private const int AdoPatLength = 52;
        private readonly int Two = '2';
        private readonly int Seven = '7';
        private readonly int A = 'a';
        private readonly int Z = 'z';
        protected bool? RunIndexOfAdoPat { get; set; }

        public virtual bool PrintMatchCount { get; set; }

        [Params(false)]
        public virtual bool FindAllMatches { get; set; }

        [Params(false)]
        public virtual bool SyntheticContentIncludesSignature { get; set; }

        [Params(1_000)]
        public int SyntheticContentSizeInKb;

        [Params(false)]
        public virtual bool UseSyntheticContent { get; set; }

        public SniffBenchmark(SniffOptions _)
        {
            InitializeSignatures();

            if (!(Signatures.Any() || RunIndexOfAdoPat.GetValueOrDefault() == true) || !RegexSignatures.Any())
            {
                throw new InvalidOperationException("The Signatures and RegexSignatures properties must be initialized in an InitializeSignatures() overload.");
            }

            if (!RunIndexOfAdoPat.HasValue)
            {
                RunIndexOfAdoPat = true;
            }

            _regexSignature = new Lazy<string>(() => String.Join("|", RegexSignatures));
        }

        protected abstract void InitializeSignatures();

        public int Run()
        {
            if (Debugger.IsAttached)
            {
                this.FindAllMatches = true;
                this.TargetContents = new Dictionary<string, string>() { { SyntheticFileName, GenerateScanTarget(1, false) } };
                this.IndexOf();
            }
            else
            {
                BenchmarkRunner.Run(this.GetType());
            }

            return 0;
        }

        [GlobalSetup]
        public virtual void GlobalSetup()
        {
            TargetContents = new Dictionary<string, string>();

            if (UseSyntheticContent)
            {
                TargetContents.Add(SyntheticFileName, GenerateScanTarget(SyntheticContentSizeInKb, SyntheticContentIncludesSignature));
            }
            else
            {
                foreach (var file in Directory.EnumerateFiles(TargetsDirectory, "*.*", SearchOption.AllDirectories))
                {
                    if (!file.Contains(".git\\"))
                    {
                        TargetContents.Add(file, File.ReadAllText(file));
                    }
                }
            }

            Console.WriteLine($"Verifying {TargetContents.Count} files");
            int totalSize = 0;
            foreach (var contentKvp in TargetContents)
            {
                var content = contentKvp.Value;
                totalSize += content.Length;
                Console.WriteLine($"{contentKvp.Key} {nameof(IndexOfInternal)}        {IndexOfInternal(content)}");
                Console.WriteLine($"{contentKvp.Key} {nameof(RE2RegexEngineInternal)} {RE2RegexEngineInternal(content)}");
            }

            Console.WriteLine($"Total size {totalSize * 2:#,##0} bytes");
        }

        [Benchmark]
        public void IndexOf()
        {
            foreach (var content in TargetContents)
            {
                IndexOfInternal(content.Value);
            }
        }

        private int IndexOfInternal(string content)
        {
            int count = 0;
            int maxLength = content.Length;
            int index = 0;

            // Analyze for literal signatures
            foreach (string signature in Signatures)
            {
                if (FindAllMatches)
                {
                    index = -signature.Length;
                    while (index != -1 && index < maxLength)
                    {
                        index = content.IndexOf(signature, index + signature.Length, StringComparison.Ordinal);
                        count++;
                    }
                }
                else
                {
                    index = content.IndexOf(signature, StringComparison.Ordinal);

                    if (index >= 0)
                    {
                        count++;
                        break;
                    }
                }
            }

            // Analyze for ADO PAT
            if (RunIndexOfAdoPat.Value)
            {
                if (FindAllMatches)
                {
                    index = -AdoPatLength;
                    while (index != -1 && index < maxLength)
                    {
                        index = AdoPatIndexOf(content, index + AdoPatLength);
                        count++;
                    }
                }
                else if (count == 0)
                {
                    index = AdoPatIndexOf(content);

                    if (index >= 0)
                    {
                        count++;
                    }
                }
            }

            if (PrintMatchCount)
            {
                Console.WriteLine($"count={count}");
            }

            return count;
        }

        private int AdoPatIndexOf(string content, int startIndex = 0)
        {
            int consecutiveChars = 0;

            int length = content.Length;
            for (int i = startIndex; i < length; i++)
            {
                var c = content[i];
                if ((Two <= c && c <= Seven) || (A <= c && c <= Z))
                {
                    consecutiveChars++;
                    if (consecutiveChars >= AdoPatLength)
                    {
                        return i + 1 - AdoPatLength;
                    }
                }
                else
                {
                    consecutiveChars = 0;
                }
            }

            return -1;
        }

        // [Benchmark]
        // public virtual void DotNetRegexEngine()
        // {
        //     foreach (var content in TargetContents)
        //     {
        //         DotNetRegexEngineInternal(content.Value);
        //     }
        // }

        // private int DotNetRegexEngineInternal(string content)
        // {
        //     int count = 0;
        //     if (FindAllMatches)
        //     {
        //         foreach (FlexMatch match in DotNetRegex.Instance.Matches(content, RegexSignature))
        //         {
        //             count++;
        //         }
        //     }
        //     else
        //     {
        //         if (DotNetRegex.Instance.IsMatch(content, RegexSignature))
        //         {
        //             count++;
        //         }
        //     }

        //     if (PrintMatchCount)
        //     {
        //         Console.WriteLine($"count={count}");
        //     }

        //     return count;
        // }

        // [Benchmark]
        // public void CachedDotNetEngine()
        // {
        //     foreach (var content in TargetContents)
        //     {
        //         CachedDotNetEngineInternal(content.Value);
        //     }
        // }

        // private int CachedDotNetEngineInternal(string content)
        // {
        //     int count = 0;
        //     if (FindAllMatches)
        //     {
        //         foreach (FlexMatch match in CachedDotNetRegex.Instance.Matches(content, RegexSignature))
        //         {
        //             count++;
        //         }
        //     }
        //     else
        //     {
        //         if (CachedDotNetRegex.Instance.IsMatch(content, RegexSignature))
        //         {
        //             count++;
        //         }

        //     }

        //     if (PrintMatchCount)
        //     {
        //         Console.WriteLine($"count={count}");
        //     }

        //     return count;
        // }

        [Benchmark]
        public void RE2RegexEngine()
        {
            foreach (var content in TargetContents)
            {
                RE2RegexEngineInternal(content.Value);
            }
        }

        private int RE2RegexEngineInternal(string content)
        {
            int count = 0;
            if (FindAllMatches)
            {
                foreach (FlexMatch match in RE2Regex.Instance.Matches(content, RegexSignature))
                {
                    count++;
                }
            }
            else
            {
                if (RE2Regex.Instance.IsMatch(content, RegexSignature))
                {
                    count++;
                }
            }

            if (PrintMatchCount)
            {
                Console.WriteLine($"count={count}");
            }

            return count;
        }

        // [Benchmark]
        // public void IronRE2Engine()
        // {
        //     int count = 0;
        //     if (FindAllMatches)
        //     {
        //         foreach (FlexMatch match in IronRE2Regex.Instance.Matches(TargetContents, RegexSignature))
        //         {
        //             count++;
        //         }
        //     }
        //     else
        //     {
        //         IronRE2Regex.Instance.IsMatch(TargetContents, RegexSignature);
        //     }
        // }

        private string GenerateScanTarget(int sizeInMegabytes, bool includeSignature)
        {
            for (int i = 0; i < 10; i++)
            {
                var target = GenerateScanTargetInternal(sizeInMegabytes, includeSignature);

                if (SyntheticContentIncludesSignature)
                {
                    return target;
                }
                else if ((RE2RegexEngineInternal(target) == 0) && (IndexOfInternal(target) == 0))
                {
                    return target;
                }

                Console.WriteLine("Generated target contents did not meet the criteria. Regenerating file.");
            }

            throw new InvalidOperationException($"Could not generate scan target that satisfied the criteria.");
        }

        private string GenerateScanTargetInternal(int sizeInMegabytes, bool includeSignature)
        {
            var sb = new StringBuilder();

            int size = sizeInMegabytes * 1024;

            while (sb.Length < size)
            {
                sb.Append($"{Guid.NewGuid()} {(includeSignature ? Signatures[DateTime.Now.Ticks % Signatures.Length] : "")} ");
            }

            return sb.ToString();
        }
    }
}
