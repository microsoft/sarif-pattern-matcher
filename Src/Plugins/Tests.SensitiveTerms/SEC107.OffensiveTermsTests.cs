// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;
using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SensitiveTerms
{
    public class OffensiveTermsTests : SensitiveTermsEndToEndTests
    {
        public OffensiveTermsTests(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected override string RuleId => "SEC107";

        protected override string Framework => "netstandard2.0";

        [Fact]
        public void DoNotUseSensitiveTerms_EndToEndFunctionalTests()
            => RunAllTests();
    }
}
