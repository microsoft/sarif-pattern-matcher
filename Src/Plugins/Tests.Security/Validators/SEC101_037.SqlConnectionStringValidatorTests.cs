// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class SqlConnectionStringValidatorTests
    {
        private const ValidationState ExpectedValidationState = ValidationState.UnknownHost;

        [Fact]
        public void SqlConnectionStringValidatorTests_Test()
        {
            string fingerprintText = "[host=server][id=account][resource=database][secret=password]";
            string message = null;
            var fingerprint = new Fingerprint(fingerprintText);
            var keyValuePairs = new Dictionary<string, string>();

            ValidationState actualValidationState = SqlConnectionStringValidator.IsValidDynamic(ref fingerprint,
                                                                                                ref message,
                                                                                                ref keyValuePairs,
                                                                                                out ResultLevelKind resultLevelKind);
            Assert.Equal(ExpectedValidationState, actualValidationState);
        }
    }
}
