// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;
using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.AzureDevOpsConfiguration
{
    public class ServiceConnectionSecurityTests : EndToEndTestsAzureDevOpsConfiguration
    {
        public ServiceConnectionSecurityTests(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected override string RuleId => "AZC102";

        protected override string Framework => "netstandard2.0";

        [Fact]
        public void AzureDevOpsConfiguration_EndToEndFunctionalTests()
            => RunAllTests();
    }
}
