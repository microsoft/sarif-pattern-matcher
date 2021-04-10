// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class NuGetCredentialsValidatorTests
    {
        private const ValidationState ExpectedValidationState = ValidationState.Unknown;

        [Fact]
        public void NuGetCredentialsValidator_Test()
        {
            string fingerprintText = "[host=<packageSources>\n    <clear />\n    <add key=\"sourceName\" value=\"https://api.nuget.org/v3/index.json\" />\n  </packageSources>][id=username][secret=password]";
            var fingerprint = new Fingerprint(fingerprintText);
            string message = null;
            var keyValuePairs = new Dictionary<string, string>();

            ValidationState actualValidationState = NuGetCredentialsValidator.IsValidDynamic(ref fingerprint, ref message, ref keyValuePairs);
            Assert.Equal(ExpectedValidationState, actualValidationState);
        }
    }
}
