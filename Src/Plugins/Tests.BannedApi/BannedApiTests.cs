﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.


using Microsoft.CodeAnalysis.SarifPatternMatcher.Test.AllPlugins;

using Xunit;
using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher.Tests.BannedApi
{
    public class BannedApiTests : EndToEndTests
    {
        protected override string TestLogResourceNameRoot
            => "Microsoft.CodeAnalysis.SarifPatternMatcher.Tests.BannedApi.TestData.BannedApi";

        public BannedApiTests(ITestOutputHelper outputHelper) : base(outputHelper) { }

        [Fact]
        public void EndToEndFunctionalTests()
            => RunAllTests();
    }
}
