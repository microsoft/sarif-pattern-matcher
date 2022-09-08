// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    [Verb("stress", HelpText = "Run various stress scenarios.")]
    internal class StressOptions : SingleFileOptionsBase
    {
    }
}
