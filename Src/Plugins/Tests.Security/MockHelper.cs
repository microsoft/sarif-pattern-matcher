// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

using Moq;
using Moq.Protected;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public static class MockHelper
    {
        /// <summary>
        /// ResetStaticInstance is a method that will invoke the static instace creation.
        /// This is required if we are injecting HttpClient, for example.
        /// </summary>
        /// <typeparam name="T">The class you want to reset.</typeparam>
        public static void ResetStaticInstance<T>()
        {
            ConstructorInfo constructor = typeof(T).GetConstructor(BindingFlags.Static | BindingFlags.NonPublic, null, new Type[0], null);
            constructor.Invoke(null, null);
        }

        public static HttpMessageHandler MockHttpMessageHandler(HttpStatusCode httpStatusCode, HttpContent httpContent)
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
    }
}
