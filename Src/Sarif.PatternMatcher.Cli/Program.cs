// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Text;

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal static class Program
    {
        [ThreadStatic]
        internal static IFileSystem FileSystem;

        [ThreadStatic]
        internal static Exception RuntimeException;

        [ThreadStatic]
        internal static AnalyzeCommand InstantiatedAnalyzeCommand;

        internal static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            try
            {
                args = EntryPointUtilities.GenerateArguments(args, FileSystem ?? new FileSystem(), new EnvironmentVariables());
                args = RewriteArgs(args);
            }
            catch (Exception ex)
            {
                RuntimeException = ex;
                Console.WriteLine(ex.ToString());
                return CommandBase.FAILURE;
            }

            bool isValidHelpCommand =
                args.Length > 0 &&
                args[0] == "help" &&
                ((args.Length == 2 && IsValidVerbName(args[1])) || args.Length == 1);

            bool isVersionCommand = args[0] == "version" && args.Length == 1;

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
                (AnalyzeOptions options) => RunAnalyzeCommand(options),
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

        internal static void ClearUnitTestData()
        {
            FileSystem = null;
            RuntimeException = null;
            InstantiatedAnalyzeCommand = null;
        }

        internal static int RunAnalyzeCommand(AnalyzeOptions options)
        {
            InstantiatedAnalyzeCommand = new AnalyzeCommand(fileSystem: FileSystem);
            return InstantiatedAnalyzeCommand.Run(options);
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
