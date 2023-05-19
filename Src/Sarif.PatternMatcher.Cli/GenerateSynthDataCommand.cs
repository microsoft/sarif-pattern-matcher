// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal class GenerateSynthDataCommand: CommandBase
    {
        public GenerateSynthDataCommand() { }

        public int Run(GenerateSynthDataOptions options)
        {
            // Create skimmers
            ISet<Skimmer<AnalyzeContext>> skimmers =
                AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(
                    new FileSystem(),
                    options.PluginFilePaths,
                    Tool.CreateFromAssemblyData());

            // For each skimmer with ContentsRegex, generate synthetic data
            foreach (Skimmer<AnalyzeContext> skimmer in skimmers)
            {
                Console.WriteLine(skimmer);
            }

            return 0;
        }
    }
}
