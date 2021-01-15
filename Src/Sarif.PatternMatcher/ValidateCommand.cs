// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;

using Microsoft.CodeAnalysis.Sarif.Driver;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class ValidateCommand : MultifileCommandBase
    {
        protected override string ProcessingName => "validated";

        public int Run(ValidateOptions options)
        {
            try
            {
                IEnumerable<FileProcessingData> filesData = GetFilesToProcess(options);

                if (!ValidateOptions(options, filesData))
                {
                    return FAILURE;
                }

                IEnumerable<string> validatorAssemblyPaths =
                    GetValidatorPaths(options.SearchDefinitionsPaths);

                var validators = new ValidatorsCache(validatorAssemblyPaths);

                foreach (FileProcessingData fileData in filesData)
                {
                    SarifLog sarifLog = fileData.SarifLog;
                    new ValidatingVisitor(validators).VisitSarifLog(sarifLog);

                    WriteSarifFile(FileSystem,
                                   fileData.SarifLog,
                                   fileData.OutputFilePath,
                                   options.Minify);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return FAILURE;
            }

            return SUCCESS;
        }

        public static IEnumerable<string> GetValidatorPaths(IEnumerable<string> searchDefinitionsPaths)
        {
            var validatorAssemblyPaths = new List<string>();

            foreach (string searchDefinitionsPath in searchDefinitionsPaths)
            {
                JsonSerializer serializer = new JsonSerializer();

                using var textReader = new StreamReader(searchDefinitionsPath);
                using var jsonReader = new JsonTextReader(textReader);

                SearchDefinitions definitions = serializer.Deserialize<SearchDefinitions>(jsonReader);

                if (!string.IsNullOrEmpty(definitions.ValidatorsAssemblyName))
                {
                    string validatorAssemblyPath = Path.GetDirectoryName(searchDefinitionsPath);
                    validatorAssemblyPath = Path.Combine(validatorAssemblyPath, definitions.ValidatorsAssemblyName);
                    validatorAssemblyPaths.Add(validatorAssemblyPath);
                }
            }

            if (validatorAssemblyPaths.Count == 0)
            {
                throw
                    new InvalidOperationException(
                        "No validator assembly paths could be retrieved from configured search definitions files.");
            }

            return validatorAssemblyPaths;
        }
    }
}
