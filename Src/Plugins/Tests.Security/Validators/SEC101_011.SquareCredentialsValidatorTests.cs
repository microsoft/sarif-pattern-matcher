// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Moq;
using Moq.Protected;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class SquareCredentialsValidatorTests
    {
        [Fact]
        public void SquareCredentialsValidator_Test()
        {
            string fingerprintText = "";
            if (string.IsNullOrEmpty(fingerprintText))
            {
                return;
            }

            string message = null;
            ResultLevelKind resultLevelKind = default;
            var fingerprint = new Fingerprint(fingerprintText);
            var keyValuePairs = new Dictionary<string, string>();

            SquareCredentialsValidator.IsValidDynamic(ref fingerprint,
                                                      ref message,
                                                      keyValuePairs,
                                                      ref resultLevelKind);
        }

        [Fact]
        public void SquareCredentialsValidator_TestingMock()
        {
            var mockMessageHandler = new Mock<HttpMessageHandler>();
            mockMessageHandler.Protected()
                .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK
                });

            SquareCredentialsValidator.SetHttpClient(new HttpClient(mockMessageHandler.Object));
            string fingerprintText = "[id=a][secret=b]";
            if (string.IsNullOrEmpty(fingerprintText))
            {
                return;
            }

            string message = null;
            ResultLevelKind resultLevelKind = default;
            var fingerprint = new Fingerprint(fingerprintText);
            var keyValuePairs = new Dictionary<string, string>();

            var state = SquareCredentialsValidator.IsValidDynamic(ref fingerprint,
                                                      ref message,
                                                      keyValuePairs,
                                                      ref resultLevelKind);
            // TODO: validate state
        }
    }
}
