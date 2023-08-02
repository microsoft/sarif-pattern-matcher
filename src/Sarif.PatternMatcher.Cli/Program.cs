// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;

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
                args = args.Length == 0 ? new string[] { "help" } : args;

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
                    ExportEventsOptions,
                    DumpEventsOptions,
                    ValidateOptions>(args)
                  .MapResult(
                    (AnalyzeOptions options) => new AnalyzeCommand().Run(options, ref GlobalContext),
                    (AnalyzeDatabaseOptions options) => new AnalyzeDatabaseCommand().Run(options),
                    (ExportConfigurationOptions options) => new ExportConfigurationCommand().Run(options),
                    (ExportRulesMetatadaOptions options) => new ExportRulesMetatadaCommand().Run(options),
                    (ExportSearchDefinitionsOptions options) => new ExportSearchDefinitionsCommand().Run(options),
                    (ImportAndAnalyzeOptions options) => new ImportAndAnalyzeCommand().Run(options),
                    (ExportEventsOptions options) => new ExportEventsCommand().Run(options),
                    (DumpEventsOptions options) => new DumpEventsCommand().Run(options),
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
            var rewritten = new List<string>();
            for (int i = 0; i < args.Length; i++)
            {
                rewritten.Add(args[i]);
                string next =
                    i + 1 < args.Length
                        ? args[i + 1]
                        : null;

                switch (args[i])
                {
                    // AnalyzeOptionsBase
                    case "-q":
                    case "--quiet":
                    case "-r":
                    case "--recurse":
                    case "-e":
                    case "--environment":
                    case "--rich-return-code":

                    // AnalyzeOptions
                    case "--retry":
                    case "--redact-secrets":
                    case "--enhanced-reporting":
                    case "--dynamic-validation":
                    case "--disable-dynamic-validation-caching":
                    {
                        if (!EvaluatesToTrueOrFalse(next))
                        {
                            rewritten.Add("True");
                        }

                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            return rewritten.ToArray();
        }

        private static bool EvaluatesToTrueOrFalse(string value)
        {
            return value == "True" || value == "False" ||
                   value == "true" || value == "false" ||
                   value == "1" || value == "0";
        }
    }
}
