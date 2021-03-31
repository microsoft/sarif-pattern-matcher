// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class HttpAuthorizationRequestHeaderValidatorTests
    {
        private const string TestHost = "http://www.host.com";
        private const string TestKey = "somekey";
        private const string TestResource = "/some-path";
        private const ValidationState ExpectedValidationState = ValidationState.NoMatch;

        [Fact]
        public void HttpAuthorizationRequestHeaderValidator_Test()
        {
            string fingerprintText = string.Format("[host={0}][secret={1}][resource={2}]", TestHost, TestKey, TestResource);
            var fingerprint = new Fingerprint(fingerprintText);
            string message = null;
            Dictionary<string, string> keyValuePairs = new Dictionary<string, string>();

            ValidationState actualValidationState = HttpAuthorizationRequestHeaderValidator.IsValidDynamic(ref fingerprint, ref message, ref keyValuePairs);
            Assert.Equal(ExpectedValidationState, actualValidationState);
        }
    }
}
