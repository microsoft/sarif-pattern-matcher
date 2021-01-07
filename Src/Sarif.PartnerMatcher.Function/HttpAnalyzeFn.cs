// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.IO;
using System.Net.Http;
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
            ILogger log,
            ExecutionContext context)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            try
            {
                IFormFile file = req.Form.Files["file"];

                using (var reader = new StreamReader(file.OpenReadStream()))
                {
                    string text = reader.ReadToEnd();
                    string rulefolder = context.FunctionDirectory;

                    log.LogInformation($"Start to analyze file");

                    string sourceFilePath = Path.Combine(@"X:\Temp", file.FileName);
                    SarifLog sariflog = await Task.Run(() => SpamAnalyzer.Analyze(sourceFilePath, text, rulefolder));

                    log.LogInformation($"Completed analyzing file");
                    return new JsonResult(sariflog);
                }
            }
            catch (Exception ex)
            {
                log.LogError(ex.ToString());
                return new BadRequestResult();
            }
        }

        [FunctionName("analyze")]
        public static async Task<IActionResult> Analyze(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req,
            ILogger log,
            ExecutionContext context)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            try
            {
                string fileName = req.Form["filename"].ToString();
                string fileContent = req.Form["filecontent"].ToString();

                string rulefolder = context.FunctionDirectory;
                log.LogInformation($"Start to analyze file");

                // AnalyzeContext requires URI to file
                string sourceFilePath = Path.Combine(@"X:\Temp", fileName);
                SarifLog sariflog = await Task.Run(() => SpamAnalyzer.Analyze(sourceFilePath, fileContent, rulefolder));

                log.LogInformation($"Completed analyzing file");

                return new JsonResult(sariflog);
            }
            catch (Exception ex)
            {
                log.LogError(ex.ToString());
                return new BadRequestResult();
            }
        }
    }
}
