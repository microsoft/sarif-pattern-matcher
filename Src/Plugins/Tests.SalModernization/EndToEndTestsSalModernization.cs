// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security;

using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SalModernization
{
    public abstract class EndToEndTestsSalModernization : EndToEndTests
    {
        public EndToEndTestsSalModernization(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected override string TestLogResourceNameRoot => $"Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SalModernization.TestData.{TypeUnderTest}";
    }
}
