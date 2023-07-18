// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommandLine;

namespace Sarif.PatternMatcher.Benchmark
{
    [Verb("regex", HelpText = "Run 'regex' benchmark (low-level per-engine search + IndexOf comparison).")]
    public class RegexOptions
    {
    }
}
