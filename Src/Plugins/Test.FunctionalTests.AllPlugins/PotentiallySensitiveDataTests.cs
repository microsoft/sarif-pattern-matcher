// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using Xunit;
using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher.Test.FunctionalTests.AllPlugins
{
    public class PotentiallySensitiveDataTests : EndToEndTests
    {
        public PotentiallySensitiveDataTests(ITestOutputHelper outputHelper) : base(outputHelper) { }

        [Fact(Skip = "No tests for now.")]
        public void EndToEndFunctionalTests_PotentiallySensitiveData()
            => RunAllTests();
    }
}
