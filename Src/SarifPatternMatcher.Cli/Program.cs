// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

using CommandLine;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher
{
    internal class Program
    {
        private static int Main(string[] args)
        {
            return Parser.Default.ParseArguments<
                AnalyzeOptions>(args)
              .MapResult(
                (AnalyzeOptions analyzeOptions) => new AnalyzeCommand().Run(analyzeOptions),
                errs => 1);
        }
    }
}
