// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommandLine;

namespace Sarif.PatternMatcher.Benchmark
{
    [Verb("sniff-full", HelpText = "Run Sniff benchmark (low-level per-engine search + IndexOf comparison) for a the complete set of signatures.")]
    public class SniffFullOptions : SniffOptions
    {
    }
}
