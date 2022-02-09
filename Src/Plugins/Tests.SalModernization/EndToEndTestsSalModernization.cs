// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators;

using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SalModernization
{
    public abstract class EndToEndTestsSalModernization : EndToEndTests
    {
        public EndToEndTestsSalModernization(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected override string TestLogResourceNameRoot => $"Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SalModernization.TestData.{TypeUnderTest}";

        protected override string ProductDirectory
        {
            get
            {
                string path = typeof(EndToEndTestsSalModernization).Assembly.Location;
                path = GitHelper.Default.GetTopLevel(path);
                return Path.Combine(path, @"src\Plugins\Tests.SalModernization");
            }
        }
    }
}
