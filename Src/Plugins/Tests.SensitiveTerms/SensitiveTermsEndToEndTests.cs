// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security;

using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SensitiveTerms
{
    public abstract class SensitiveTermsEndToEndTests : EndToEndTests
    {
        public SensitiveTermsEndToEndTests(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected override string TestLogResourceNameRoot => $"Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SensitiveTerms.TestData.{TypeUnderTest}";

        protected override string ProductDirectory
        {
            get
            {
                string path = typeof(SensitiveTermsEndToEndTests).Assembly.Location;
                path = GitHelper.Default.GetTopLevel(path);
                return Path.Combine(path, @"src\Plugins\Tests.SensitiveTerms");
            }
        }
    }
}
