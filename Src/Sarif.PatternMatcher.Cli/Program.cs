// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.Writers;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal static class Program
    {
        [ThreadStatic]
        internal static AnalyzeContext GlobalContext;

        internal static int Main(string[] args)
        {
            try
            {
                Console.OutputEncoding = Encoding.UTF8;
                GlobalContext ??= new AnalyzeContext();

                // TBD FileSystem.Instance??
                GlobalContext.FileSystem ??= new FileSystem();

                // TBD Environment variables to context
                args = EntryPointUtilities.GenerateArguments(args, GlobalContext.FileSystem, new EnvironmentVariables());
                args = RewriteArgs(args);

                bool isValidHelpCommand =
                    args.Length > 0 &&
                    args[0] == "help" &&
                    ((args.Length == 2 && IsValidVerbName(args[1])) || args.Length == 1);

                bool isVersionCommand = args.Length == 1 && args[0] == "version";

                isVersionCommand = args[0] == "version";

                return Parser.Default.ParseArguments<
                    AnalyzeOptions,
                    AnalyzeDatabaseOptions,
                    ExportConfigurationOptions,
                    ExportRulesMetatadaOptions,
                    ExportSearchDefinitionsOptions,
                    ImportAndAnalyzeOptions,
                    StressOptions,
                    ValidateOptions>(args)
                  .MapResult(
                    (AnalyzeOptions options) => new AnalyzeCommand().Run(options, ref GlobalContext),
                    (AnalyzeDatabaseOptions options) => new AnalyzeDatabaseCommand().Run(options),
                    (ExportConfigurationOptions options) => new ExportConfigurationCommand().Run(options),
                    (ExportRulesMetatadaOptions options) => new ExportRulesMetatadaCommand().Run(options),
                    (ExportSearchDefinitionsOptions options) => new ExportSearchDefinitionsCommand().Run(options),
                    (ImportAndAnalyzeOptions options) => new ImportAndAnalyzeCommand().Run(options),
                    (StressOptions options) => new StressCommand().Run(options),
                    (ValidateOptions options) => new ValidateCommand().Run(options),
                    _ => isValidHelpCommand || isVersionCommand
                            ? CommandBase.SUCCESS
                            : CommandBase.FAILURE);
            }
            catch (Exception ex)
            {
                Errors.LogUnhandledEngineException(GlobalContext, ex);
                GlobalContext.RuntimeErrors |= RuntimeConditions.ExceptionProcessingCommandline;
                GlobalContext.RuntimeExceptions ??= new List<Exception>();
                GlobalContext.RuntimeExceptions.Add(ex);
                return CommandBase.FAILURE;
            }
        }

        internal static void ClearUnitTestData()
        {
            GlobalContext = null;
        }

        private static bool IsValidVerbName(string verb)
        {
            return
                verb == "analyze" ||
                verb == "analyze-database" ||
                verb == "export-rules" ||
                verb == "export-search-definitions" ||
                verb == "import-analyze" ||
                verb == "stress";
        }

        private static string[] RewriteArgs(string[] args)
        {
            bool hasObsoleteArgument = false;
            bool hasCurrentFileSizeArg = false;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--file-size-in-kb")
                {
                    hasObsoleteArgument = true;
                    args[i] = "--max-file-size-in-kb";

                    Console.WriteLine("Please update the command line arguments: `--file-size-in-kb` " +
                        "should be replaced with `--max-file-size-in-kb`.");
                }
                else if (args[i] == "--max-file-size-in-kb")
                {
                    hasCurrentFileSizeArg = true;
                }

                if (hasObsoleteArgument && hasCurrentFileSizeArg)
                {
                    string message = $"Both `--max-file-size-in-kb` and `--file-size-in-kb` were used. "
                        + "Please remove the obsolete option `--file-size-in-kb`.";

                    throw new ArgumentException(message);
                }
            }

            return args;
        }
    }
}
