// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Moq;
using Moq.Protected;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers
{
    public class HttpMockHelper : DelegatingHandler
    {
        private readonly List<Tuple<HttpRequestMessage, HttpStatusCode, HttpContent>> _fakeResponses =
            new List<Tuple<HttpRequestMessage, HttpStatusCode, HttpContent>>();

        public void Mock(HttpRequestMessage httpRequestMessage, HttpStatusCode httpStatusCode, HttpContent httpContent)
        {
            _fakeResponses.Add(new Tuple<HttpRequestMessage, HttpStatusCode, HttpContent>(httpRequestMessage, httpStatusCode, httpContent));
        }

        public void Clear()
        {
            _fakeResponses.Clear();
        }

        public static HttpMessageHandler Mock(HttpStatusCode httpStatusCode, HttpContent httpContent)
        {
            var mockMessageHandler = new Mock<HttpMessageHandler>();
            mockMessageHandler.Protected()
                .Setup<Task<HttpResponseMessage>>("SendAsync", ItExpr.IsAny<HttpRequestMessage>(), ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = httpStatusCode,
                    Content = httpContent
                });

            return mockMessageHandler.Object;
        }

        public bool CompareHeaders(HttpRequestHeaders headers1, HttpRequestHeaders headers2)
        {
            foreach (KeyValuePair<string, IEnumerable<string>> header in headers1)
            {
                string headerName = header.Key;
                if (!headers2.TryGetValues(headerName, out IEnumerable<string> values))
                {
                    return false;
                }

                string headerContent1 = string.Join(",", header.Value);
                string headerContent2 = string.Join(",", values);

                if (headerContent1 != headerContent2)
                {
                    return false;
                }
            }

            return true;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Tuple<HttpRequestMessage, HttpStatusCode, HttpContent> fakeResponse;

            if (request.Headers.IsEmptyEnumerable())
            {
                fakeResponse = _fakeResponses.Find(fr =>
                    fr.Item1.RequestUri == request.RequestUri
                    && fr.Item1.Headers.IsEmptyEnumerable());
            }
            else
            {
                fakeResponse = _fakeResponses.Find(fr =>
                    fr.Item1.RequestUri == request.RequestUri
                    && CompareHeaders(request.Headers, fr.Item1.Headers));
            }

            return Task.FromResult(
                new HttpResponseMessage(fakeResponse.Item2)
                {
                    RequestMessage = request,
                    Content = fakeResponse.Item3
                });
        }
    }

    public struct HttpMockTestCase
    {
        public string Title { get; set; }

        // Inputs
        public List<HttpContent> HttpContents { get; set; }
        public List<HttpStatusCode> HttpStatusCodes { get; set; }
        public List<HttpRequestMessage> HttpRequestMessages { get; set; }

        // Expected Outputs
        public string ExpectedMessage { get; set; }
        public ValidationState ExpectedValidationState { get; set; }
    }
}
