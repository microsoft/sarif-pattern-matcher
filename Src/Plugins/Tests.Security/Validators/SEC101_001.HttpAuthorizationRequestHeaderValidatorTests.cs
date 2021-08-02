// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    [Collection("MockHttpTesets")]
    public class HttpAuthorizationRequestHeaderValidatorTests
    {
        private const string TestScheme = "http";
        private const string TestKey = "somekey";
        private const string TestHost = "www.host.com";
        private const string TestResource = "/some-path";
        private const ValidationState ExpectedValidationState = ValidationState.NoMatch;

        [Fact]
        public void HttpAuthorizationRequestHeaderValidator_Test()
        {
            string fingerprintText = string.Format("[host={0}][resource={1}][scheme={2}][secret={3}]", TestHost, TestResource, TestScheme, TestKey);

            string message = null;
            ResultLevelKind resultLevelKind = default;
            var fingerprint = new Fingerprint(fingerprintText);
            var keyValuePairs = new Dictionary<string, string>();

            ValidationState actualValidationState = HttpAuthorizationRequestHeaderValidator.IsValidDynamic(ref fingerprint,
                                                                                                           ref message,
                                                                                                           keyValuePairs,
                                                                                                           ref resultLevelKind);
            Assert.Equal(ExpectedValidationState, actualValidationState);
        }
    }
}
