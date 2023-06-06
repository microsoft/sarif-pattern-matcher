// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security;

using Xunit.Abstractions;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.AzureDevOpsConfiguration
{
    public abstract class EndToEndTestsAzureDevOpsConfiguration : EndToEndTests
    {
        public EndToEndTestsAzureDevOpsConfiguration(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected override string TestLogResourceNameRoot => $"Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.AzureDevOpsConfiguration.TestData.{TypeUnderTest}";

    }
}
