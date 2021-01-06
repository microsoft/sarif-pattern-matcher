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
    public static class HttpAnalyzeFn
    {
        [FunctionName("SpamCheck")]
        public static async Task<IActionResult> SpamCheck(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req,
            //[Queue("outqueue"), StorageAccount("AzureWebJobsStorage")] ICollector<SarifLog> msg,
            ILogger log,
            ExecutionContext context)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            try
            {
                var file = req.Form.Files["file"];

                StreamReader reader = new StreamReader(file.OpenReadStream());
                var text = reader.ReadToEnd();



                log.LogInformation($"Function Dir: {context.FunctionDirectory}, App Dir: {context.FunctionDirectory}");
                string rulefolder = context.FunctionDirectory;
                log.LogInformation($"Analyze file");
                var sourceFilePath = Path.Combine(@"X:\Temp", file.FileName);
                var sariflog = SpamAnalyzer.Analyze(sourceFilePath, text, rulefolder);
                return new JsonResult(sariflog);
            }
            catch (Exception ex)
            {
                log.LogError(ex.ToString());
                return new JsonResult(new { ErrorMessage = ex.Message });
            }
        }

        [FunctionName("analyze")]
        public static async Task<IActionResult> analyze(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req,
            ILogger log,
            ExecutionContext context)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            try
            {
                var fileName = req.Form["filename"];
                var fileContent = req.Form["filecontent"];

                log.LogInformation($"Function Dir: {context.FunctionDirectory}, App Dir: {context.FunctionDirectory}");
                string rulefolder = context.FunctionDirectory;
                log.LogInformation($"Analyze file");

                // AnalyzeContext requires URI to file
                var sourceFilePath = Path.Combine(@"X:\Temp", fileName);
                var sariflog = SpamAnalyzer.Analyze(sourceFilePath, fileContent, rulefolder);
                return new JsonResult(sariflog);
            }
            catch (Exception ex)
            {
                log.LogError(ex.ToString());
                return new JsonResult(new { ErrorMessage = ex.Message });
            }
        }

    }
}
