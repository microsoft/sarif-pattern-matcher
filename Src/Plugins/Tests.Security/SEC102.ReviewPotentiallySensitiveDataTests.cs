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

        protected override string Framework => "netstandard2.0";

        [Fact]
        public void ReviewPotentiallySensitiveData_EndToEndFunctionalTests()
            => RunAllTests();

        [Fact]
        public void ReviewPotentiallySensitiveData_ValidateOutputFiles()
            => ValidateOutputFiles();
    }
}
