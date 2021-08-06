// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class SqlCredentialsValidatorTests
    {
        [Fact]
        public void SqlCredentialsValidatorTests_Test()
        {
            string fingerprintText = "[host=server][id=account][resource=database][secret=password]";
            string message = null;
            ResultLevelKind resultLevelKind = default;
            var fingerprint = new Fingerprint(fingerprintText);
            var keyValuePairs = new Dictionary<string, string>();

            ValidationState actualValidationState = SqlCredentialsValidator.IsValidDynamic(ref fingerprint,
                                                                                           ref message,
                                                                                           keyValuePairs,
                                                                                           ref resultLevelKind);
            Assert.True(actualValidationState == ValidationState.Unknown || actualValidationState == ValidationState.UnknownHost);
        }
    }
}
