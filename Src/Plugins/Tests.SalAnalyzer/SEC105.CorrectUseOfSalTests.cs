// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;
using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SalAnalyzer
{
    public class CorrectUseOfSalTests : EndToEndTests
    {
        public CorrectUseOfSalTests(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected override string RuleId => "SEC105";

        // TODO the test project is targeting netcoreapp3.1
        protected override string Framework => "netstandard2.0";

        [Fact]
        public void CorrectUseOfSal_EndToEndFunctionalTests()
            => RunAllTests();
    }
}
