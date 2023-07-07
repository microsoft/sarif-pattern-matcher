// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;
using Xunit.Abstractions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class SecurePlaintextSecretsTests : EndToEndTests
    {
        public SecurePlaintextSecretsTests(ITestOutputHelper outputHelper) : base(outputHelper)
        {
        }

        protected override string RuleId => "SEC101";

        protected override string Framework => "netstandard2.1";

        protected override string TypeUnderTest => "SecurePlaintextSecrets";

        [Fact]
        [Trait(TestTraits.WindowsOnly, "true")]
        public void SecurePlaintextSecrets_EndToEndFunctionalTests()
            => RunAllTests();

        [Fact]
        public void SecurePlaintextSecrets_VerifyAllValidatorsExist()
        {
            PatternInvariantTests.VerifyAllValidatorsExist(DefinitionsPath);
        }
    }
}
