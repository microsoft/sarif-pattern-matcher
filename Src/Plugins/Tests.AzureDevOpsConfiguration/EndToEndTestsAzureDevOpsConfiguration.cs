// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security;

using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.AzureDevOpsConfiguration
{
    public abstract class EndToEndTestsAzureDevOpsConfiguration : EndToEndTests
    {
        public EndToEndTestsAzureDevOpsConfiguration(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected override string TestLogResourceNameRoot => $"Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.AzureDevOpsConfiguration.TestData.{TypeUnderTest}";

        protected override string ProductDirectory
        {
            get
            {
                string path = typeof(EndToEndTestsAzureDevOpsConfiguration).Assembly.Location;
                path = GitHelper.Default.GetTopLevel(path);
                return Path.Combine(path, @"src\Plugins\Tests.AzureDevOpsConfiguration");
            }
        }
    }
}
