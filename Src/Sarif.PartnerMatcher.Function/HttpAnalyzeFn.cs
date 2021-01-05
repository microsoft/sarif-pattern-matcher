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
        public static async Task<IActionResult> Run(
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

    }
}
