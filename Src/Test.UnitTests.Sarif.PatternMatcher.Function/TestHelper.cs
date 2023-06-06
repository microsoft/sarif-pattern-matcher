// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.IO;

using Microsoft.AspNetCore.Http;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Primitives;

using Moq;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Function
{
    public static class TestHelper
    {
#pragma warning disable CA2211 // Non-constant fields should not be visible
        public static string SampleCode = @"
                namespace AnalysisTestProject2
                {
                    internal class Class4
                    {
                    }
                }
                "
#pragma warning restore CA2211 // Non-constant fields should not be visible
;

        public static HttpRequest MockAnalyzeFunctionRequest(string fileName, string fileContent)
        {
            var formData = new Dictionary<string, StringValues>
            {
                { FunctionConstants.FileNamePropertyName, fileName },
                { FunctionConstants.FileContentPropertyName, fileContent }
            };
            return HttpRequestSetup(formData);
        }

        public static HttpRequest HttpRequestSetup(Dictionary<string, StringValues> formData)
        {
            var requestMock = new Mock<HttpRequest>();
            requestMock.Setup(req => req.Form).Returns(new FormCollection(formData));
            return requestMock.Object;
        }

        public static ExecutionContext ContextSetup()
        {
            // no need to mock 
            return new ExecutionContext { FunctionDirectory = Path.GetFullPath(@".\") };
        }

        public static string GetTestResourceContent(string fileName)
        {
            string filePath = Path.Combine(@".\TestData\", fileName);
            return File.ReadAllText(filePath);
        }
    }
}
