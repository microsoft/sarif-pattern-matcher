// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;
using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Security
{
    public class ReviewPotentiallySensitiveDataTests : EndToEndTests
    {
        public ReviewPotentiallySensitiveDataTests(ITestOutputHelper outputHelper) : base(outputHelper) { }

        protected override string RuleId => "SEC1002";

        [Fact]
        public void ReviewPotentiallySensitiveData_EndToEndFunctionalTests()
            => RunAllTests();
    }
}
