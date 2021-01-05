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
    public static class HttpSpamCheckFn
    {
        [FunctionName("analyze")]
        public static async Task<IActionResult> Run(
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
