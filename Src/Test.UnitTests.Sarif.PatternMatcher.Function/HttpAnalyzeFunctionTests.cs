// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

using FluentAssertions;

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

using Test.UnitTest.Sarif.PatternMatcher.Function;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Function
{
    public class HttpAnalyzeFunctionTests
    {
        private readonly ILogger logger = new TestLogger();

        [Fact]
        public async Task Function_HttpAnalyze_NormalFileContent_Should_Return_SarifLog()
        {
            IActionResult result = await HttpAnalyzeFunction.Analyze(
                request: TestHelper.MockAnalyzeFunctionRequest("abc.cs", TestHelper.SampleCode),
                log: logger,
                context: TestHelper.ContextSetup());

            var resultObject = (OkObjectResult)result;

            resultObject.Should().NotBeNull();
            resultObject.StatusCode.Should().Be((int)HttpStatusCode.OK);
            resultObject.Value.Should().NotBeNull();

            var sarifLog = resultObject.Value as SarifLog;
            sarifLog.Should().NotBeNull();
            sarifLog.Runs.Count.Should().Be(1);
        }

        [Fact]
        public async Task Function_HttpAnalyze_FileWithPAT_Should_Return_SarifLog()
        {
            string patTextFile = "SEC101.AzureDevOpsPersonalAccessToken_pats.txt";
            IActionResult result = await HttpAnalyzeFunction.Analyze(
                request: TestHelper.MockAnalyzeFunctionRequest(patTextFile, TestHelper.GetTestResourceContent(patTextFile)),
                log: logger,
                context: TestHelper.ContextSetup());

            var resultObject = (OkObjectResult)result;
            resultObject.Should().NotBeNull();
            resultObject.StatusCode.Should().Be((int)HttpStatusCode.OK);
            resultObject.Value.Should().NotBeNull();

            var sarifLog = resultObject.Value as SarifLog;
            sarifLog.Should().NotBeNull();
            sarifLog.Runs.Count.Should().Be(1);

            var results = sarifLog.Runs[0].Results;
            results.Should().NotBeNull();

            // 4 results: 2 warning 2 not applicable
            results.Should().NotBeEmpty();
            results.Count(r => r.Level == FailureLevel.Warning).Should().Be(2);
            results.FirstOrDefault(r => r.Level == FailureLevel.Warning)?.RuleId.Should().StartWith("SEC101");
        }

        [Fact]
        public async Task Function_HttpAnalyze_WithoutFileName_Should_Return_OK()
        {
            IActionResult result = await HttpAnalyzeFunction.Analyze(
                request: TestHelper.HttpRequestSetup(new Dictionary<string, StringValues> { { FunctionConstants.FileContentPropertyName, TestHelper.SampleCode } }),
                log: logger,
                context: TestHelper.ContextSetup());

            var resultObject = (OkObjectResult)result;
            resultObject.Should().NotBeNull();
            resultObject.StatusCode.Should().Be((int)HttpStatusCode.OK);
        }

        [Fact]
        public async Task Function_HttpAnalyze_WithoutFileContent_Should_Return_BadRequest()
        {
            IActionResult result = await HttpAnalyzeFunction.Analyze(
                request: TestHelper.HttpRequestSetup(new Dictionary<string, StringValues> { { FunctionConstants.FileNamePropertyName, "ExtensionMethods.cs" } }),
                log: logger,
                context: TestHelper.ContextSetup());

            var resultObject = (BadRequestResult)result;
            resultObject.Should().NotBeNull();
            resultObject.StatusCode.Should().Be((int)HttpStatusCode.BadRequest);
        }

        [Fact]
        public async Task Function_HttpAnalyze_WithEmptyFileName_Should_Return_OK()
        {
            IActionResult result = await HttpAnalyzeFunction.Analyze(
                request: TestHelper.MockAnalyzeFunctionRequest(string.Empty, TestHelper.SampleCode),
                log: logger,
                context: TestHelper.ContextSetup());

            var resultObject = (OkObjectResult)result;
            resultObject.Should().NotBeNull();
            resultObject.StatusCode.Should().Be((int)HttpStatusCode.OK);
        }
    }
}
