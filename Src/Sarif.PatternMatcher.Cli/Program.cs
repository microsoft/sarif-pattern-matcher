// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            return Parser.Default.ParseArguments<
                AnalyzeOptions,
                ValidateOptions>(args)
              .MapResult(
                (AnalyzeOptions options) => new AnalyzeCommand().Run(options),
                (ValidateOptions options) => new ValidateCommand().Run(options),
                _ => CommandBase.FAILURE);
        }
    }
}
