// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Threading.Tasks;
using System.Web.Http;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Function
{
    public static class HttpAnalyzeFunction
    {
        [FunctionName("analyze")]
        public static async Task<IActionResult> Analyze(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest request,
            ILogger log,
            ExecutionContext context)
        {
            if (!request.Form.ContainsKey(FunctionConstants.FileContentPropertyName))
            {
                return new BadRequestResult();
            }

            try
            {
                string fileName = "temp.txt";
                string fileContent = request.Form[FunctionConstants.FileContentPropertyName].ToString();
                if (request.Form.ContainsKey(FunctionConstants.FileNamePropertyName)
                    && !string.IsNullOrWhiteSpace(request.Form[FunctionConstants.FileNamePropertyName].ToString()))
                {
                    fileName = request.Form[FunctionConstants.FileNamePropertyName].ToString();
                }

                string definitionsFolder = context.FunctionDirectory;
                log.LogInformation($"Start to analyze text of {fileName}");

                // AnalyzeContext requires URI to file
                string sourceFilePath = $"{fileName}";
                SarifLog sariflog = await Task.Run(() => SpamAnalyzer.Analyze(sourceFilePath, fileContent, definitionsFolder));
                if (sariflog.Runs.Count > 0)
                {
                    sariflog.Runs[0].Tool.Driver.Name = "SPAM";
                }

                log.LogInformation($"Completed analyzing text of {fileName}");

                return new OkObjectResult(sariflog);
            }
            catch (Exception ex)
            {
                log.LogError(ex, ex.Message);
                return new InternalServerErrorResult();
            }
        }
    }
}
