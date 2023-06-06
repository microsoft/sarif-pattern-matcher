// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    /// <summary>
    /// Testing SEC101/038.PostgreSqlCredentialsValidator
    /// </summary>
    public class PostgreSqlCredentialsValidatorTests
    {
        private const ValidationState ExpectedValidationState = ValidationState.Unknown;

        [Fact]
        public void PostgreSqlCredentialsValidator_Test()
        {
            string fingerprintText = "[host=99.9.9.99][id=accoutName][resource=database][secret=password]";

            string message = null;
            ResultLevelKind resultLevelKind = default;
            var fingerprint = new Fingerprint(fingerprintText);
            var keyValuePairs = new Dictionary<string, string>();

            var postgreSqlCredentialsValidator = new PostgreSqlCredentialsValidator();
            ValidationState actualValidationState = postgreSqlCredentialsValidator.IsValidDynamic(ref fingerprint,
                                                                                                  ref message,
                                                                                                  keyValuePairs,
                                                                                                  ref resultLevelKind);
            Assert.Equal(ExpectedValidationState, actualValidationState);
        }

        [Fact]
        public void PostgreSqlCredentialsValidator_DebugFingerprint()
        {
            string fingerprintText = "[host=place.location.com][id=database][secret=password]";
            string message = "";
            ResultLevelKind resultLevelKind = default;
            var options = new Dictionary<string, string>();
            var fingerprint = new Fingerprint(fingerprintText);

            ValidationState expectedState = ValidationState.UnknownHost;

            var postgreSqlCredentialsValidator = new PostgreSqlCredentialsValidator();
            ValidationState actualState = postgreSqlCredentialsValidator.IsValidDynamic(ref fingerprint, ref message, options, ref resultLevelKind);

            Assert.Equal(expectedState, actualState);
        }

    }
}
