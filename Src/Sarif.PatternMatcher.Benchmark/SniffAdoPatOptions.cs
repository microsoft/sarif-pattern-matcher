// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommandLine;

namespace Sarif.PatternMatcher.Benchmark
{
    [Verb("sniff-adopat", HelpText = "Run Sniff benchmark (low-level per-engine search + IndexOf comparison) for an ADO PAT signature.")]
    public class SniffAdoPatOptions : SniffOptions
    {
    }
}
