// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;
using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class UseSecureApiTests : EndToEndTests
    {
        public UseSecureApiTests(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected override string RuleId => "SEC104";

        protected override string Framework => "netstandard2.0";

        [Fact]
        public void UseSecureApi_EndToEndFunctionalTests()
            => RunAllTests();

        [Fact]
        public void UseSecureApi_ValidateOutputFiles()
            => ValidateOutputFiles();
    }
}
