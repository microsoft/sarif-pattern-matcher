// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.IO;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Function
{
    public static class HttpAnalyzeFunction
    {
        [FunctionName("analyze-file")]
        public static async Task<IActionResult> AnalyzeFile(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest request,
            ILogger log,
            ExecutionContext context)
        {
            try
            {
                IFormFile file = request.Form.Files["file"];

                using (var reader = new StreamReader(file.OpenReadStream()))
                {
                    string text = await reader.ReadToEndAsync();
                    string definitionsFolder = context.FunctionDirectory;

                    log.LogInformation($"Start to analyze file {file.FileName}");

                    string sourceFilePath = $"file://{file.FileName}";
                    SarifLog sariflog = await Task.Run(() => SpamAnalyzer.Analyze(sourceFilePath, text, definitionsFolder));

                    log.LogInformation($"Completed analyzing file {file.FileName}");
                    return new JsonResult(sariflog);
                }
            }
            catch (Exception ex)
            {
                log.LogError(ex, ex.Message);
                return new BadRequestResult();
            }
        }

        [FunctionName("analyze-text")]
        public static async Task<IActionResult> AnalyzeText(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest request,
            ILogger log,
            ExecutionContext context)
        {
            try
            {
                string fileName = request.Form["filename"].ToString();
                string fileContent = request.Form["filecontent"].ToString();

                string definitionsFolder = context.FunctionDirectory;
                log.LogInformation($"Start to analyze text of {fileName}");

                // AnalyzeContext requires URI to file
                string sourceFilePath = $"file://{fileName}";
                SarifLog sariflog = await Task.Run(() => SpamAnalyzer.Analyze(sourceFilePath, fileContent, definitionsFolder));

                log.LogInformation($"Completed analyzing text of {fileName}");

                return new JsonResult(sariflog);
            }
            catch (Exception ex)
            {
                log.LogError(ex, ex.Message);
                return new BadRequestResult();
            }
        }
    }
}
