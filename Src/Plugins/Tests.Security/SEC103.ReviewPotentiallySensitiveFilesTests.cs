﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;
using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class ReviewPotentiallySensitiveFilesTests : EndToEndTests
    {
        public ReviewPotentiallySensitiveFilesTests(ITestOutputHelper outputHelper) : base(outputHelper) { }

        protected override string RuleId => "SEC103";

        [Fact]
        public void ReviewPotentiallySensitiveFiles_EndToEndFunctionalTests()
            => RunAllTests();
    }
}
