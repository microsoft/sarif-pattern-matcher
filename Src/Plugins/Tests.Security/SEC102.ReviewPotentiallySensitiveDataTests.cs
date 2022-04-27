// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;
using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class ReviewPotentiallySensitiveDataTests : EndToEndTests
    {
        public ReviewPotentiallySensitiveDataTests(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected override string RuleId => "SEC102";

        protected override string Framework => "netstandard2.1";

        protected override string PluginName => "ReviewPotentiallySensitiveData";

        [Fact]
        public void ReviewPotentiallySensitiveData_EndToEndFunctionalTests()
            => RunAllTests();
    }
}
