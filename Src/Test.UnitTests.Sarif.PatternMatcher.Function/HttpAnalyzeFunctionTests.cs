// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
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
            const string patTextFile = "SEC101_102.AdoPat.txt";
            IActionResult result = await HttpAnalyzeFunction.Analyze(
                request: TestHelper.MockAnalyzeFunctionRequest(patTextFile, TestHelper.GetTestResourceContent(patTextFile)),
                log: logger,
                context: TestHelper.ContextSetup());

            ValidateResult(string.Empty, result, runCount: 1, resultCount: 1, FailureLevel.Note, ignoreRegionContent: true);
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

        [Fact]
        public async Task Function_HttpAnalyze_WithFileContent_Should_Return_DifferentResponses()
        {
            const string patTextFile = "SEC101_005.SlackApiKey.py";
            string content = TestHelper.GetTestResourceContent(patTextFile);
            string[] lines = content.Split(Environment.NewLine);

            IActionResult result = await HttpAnalyzeFunction.Analyze(
                request: TestHelper.MockAnalyzeFunctionRequest(patTextFile, lines[0]),
                log: logger,
                context: TestHelper.ContextSetup());
            ValidateResult(lines[0], result, runCount: 1, resultCount: 1, FailureLevel.Note);

            result = await HttpAnalyzeFunction.Analyze(
               request: TestHelper.MockAnalyzeFunctionRequest(patTextFile, lines[1]),
               log: logger,
               context: TestHelper.ContextSetup());
            ValidateResult(lines[1], result, runCount: 1, resultCount: 0);
        }

        private static void ValidateResult(string text, IActionResult result, int runCount, int resultCount, FailureLevel failureLevel = FailureLevel.None, bool ignoreRegionContent = false)
        {
            var resultObject = (OkObjectResult)result;
            resultObject.Should().NotBeNull();
            resultObject.StatusCode.Should().Be((int)HttpStatusCode.OK);
            resultObject.Value.Should().NotBeNull();

            var sarifLog = resultObject.Value as SarifLog;
            sarifLog.Should().NotBeNull();
            sarifLog.Runs.Count.Should().Be(runCount);

            IList<Result> results = sarifLog.Runs[0].Results;

            if (resultCount == 0)
            {
                results.Should().BeNull();
                return;
            }

            results.Should().NotBeEmpty();
            results.Count(r => r.Level == failureLevel).Should().Be(resultCount);

            if (!ignoreRegionContent)
            {
                results[0].Locations[0].PhysicalLocation.ContextRegion.Snippet.Text.Should().Contain(text);
                results[0].Locations[0].PhysicalLocation.Region.Snippet.Text.Should().Contain(text);
            }
        }
    }
}
