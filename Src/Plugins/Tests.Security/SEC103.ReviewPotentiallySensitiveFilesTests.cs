// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;
using Xunit.Abstractions;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class ReviewPotentiallySensitiveFilesTests : EndToEndTests
    {
        public ReviewPotentiallySensitiveFilesTests(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected override string RuleId => "SEC103";

        protected override string Framework => "netstandard2.1";

        protected override string TypeUnderTest => "ReviewPotentiallySensitiveFiles";

        [Fact]
        public void ReviewPotentiallySensitiveFiles_EndToEndFunctionalTests()
            => RunAllTests();
    }
}
