// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;

using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SalAnalyzer
{
    public abstract class EndToEndTestsSalAnalyzer : EndToEndTests
    {
        public EndToEndTestsSalAnalyzer(ITestOutputHelper outputHelper) : base(outputHelper) { }

        protected override string TestLogResourceNameRoot => $"Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SalAnalyzer.TestData.{TypeUnderTest}";

        protected override string ProductDirectory
        {
            get
            {
                // TODO: why was this wrong?
                string path = typeof(EndToEndTestsSalAnalyzer).Assembly.Location;
                path = Path.GetDirectoryName(GitHelper.Default.GetTopLevel(path));
                return Path.Combine(path, @"Plugins\Tests.SalAnalyzer");

                //string dll = typeof(EndToEndTestsSalAnalyzer).Assembly.Location;
                //string path = Path.GetDirectoryName(dll);
                //return path;
            }
        }
    }
}
