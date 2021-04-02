// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class PostgreSqlConnectionStringValidatorTests
    {
        private const ValidationState ExpectedValidationState = ValidationState.Unknown;

        [Fact]
        public void PostgreSqlConnectionStringValidator_Test()
        {
            string fingerprintText = "[host=99.9.9.99][id=accoutName][resource=database][secret=password]";
            var fingerprint = new Fingerprint(fingerprintText);
            string message = null;
            var keyValuePairs = new Dictionary<string, string>();

            ValidationState actualValidationState = PostgreSqlConnectionStringValidator.IsValidDynamic(ref fingerprint, ref message, ref keyValuePairs);
            Assert.Equal(ExpectedValidationState, actualValidationState);
        }
    }
}
