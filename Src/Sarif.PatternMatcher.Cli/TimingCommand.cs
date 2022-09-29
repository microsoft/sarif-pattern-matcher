// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.Multitool;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal class TimingCommand : CommandBase
    {
        private static int filesScanned = 0;
        private readonly List<Tuple<string, long, long>> fileDataTupleList = new List<Tuple<string, long, long>>();
        private readonly IFileSystem fileSystem = Sarif.FileSystem.Instance;

        public int Run(TimingOptions options)
        {
            Console.WriteLine("Starting Timing Tests!");

            List<string> filesToSearch = GetWhatFilesToSearch(options);

            ISet<Skimmer<AnalyzeContext>> skimmers = AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(fileSystem, options.SearchDefinitionsPaths);

            Console.WriteLine($"Number of regexes: {GetNumberOfRegexes(options.SearchDefinitionsPaths)}");
            var totalRunTimer = new Stopwatch();
            totalRunTimer.Start();
            foreach (string filePath in filesToSearch)
            {
                Console.WriteLine($"Scanning file: {filesScanned} of {filesToSearch.Count}");
                TimeScanFileWithSkimmers(filePath, skimmers);
                filesScanned++;
            }

            totalRunTimer.Stop();
            ExportSizeAndExecutionTime(totalRunTimer.Elapsed);

            Console.WriteLine($"Timing Tests Finished. Total Runtime: {totalRunTimer.Elapsed}");
            return SUCCESS;
        }

        public void ExportSizeAndExecutionTime(TimeSpan totalRunTime)
        {
            // output Tuple list to csv in 3 columns
            var sb = new StringBuilder($"Filename, File Size in KB, Runtime in ms, Total RunTime: {totalRunTime}{Environment.NewLine}");

            foreach (Tuple<string, long, long> runData in fileDataTupleList)
            {
                sb.AppendLine($"{runData.Item1}, {runData.Item2}, {runData.Item3}");
            }

            File.WriteAllText("C:\\Users\\hulonjenkins\\OneDrive - Microsoft\\Documents\\HulonDesk\\FileSizeToRuntimeData.csv", sb.ToString());
        }

        private List<string> GetWhatFilesToSearch(TimingOptions options)
        {
            // Get a list of files to search
            IEnumerable<string> folderToSearch = options.TargetFileSpecifiers;
            var filesToSearch = new List<string>();
            foreach (string folder in folderToSearch)
            {
                filesToSearch.AddRange(Directory.GetFiles(folder, "*", SearchOption.AllDirectories).ToList<string>());
            }

            return filesToSearch;
        }

        private void TimeScanFileWithSkimmers(string filePath, ISet<Skimmer<AnalyzeContext>> skimmers)
        {
            string resourceContent = fileSystem.FileReadAllText(filePath);
            long fileSizeInBytes = fileSystem.FileInfoLength(filePath);
            int milliSecondTimeout = 60000;

            var timer = new Stopwatch();
            timer.Start();

            // Critical Section Being Timed
            {
                var logger = new AdoLogger();

                // Set up Context
                var context = new AnalyzeContext
                {
                    TargetUri = new Uri(filePath, UriKind.RelativeOrAbsolute),
                    FileContents = resourceContent,
                    Logger = logger,
                    FileRegionsCache = new FileRegionsCache(),
                };

                var disabledSkimmers = new HashSet<string>();
                IEnumerable<Skimmer<AnalyzeContext>> applicableSkimmers = AnalyzeCommand.DetermineApplicabilityForTargetHelper(context, skimmers, disabledSkimmers);

                logger.AnalysisStarted();
                // Run analyze
                using (context)
                {
                    // Implement 60 second timeout
                    Task analyzeCommandTask = Task.Factory.StartNew(() => AnalyzeCommand.AnalyzeTargetHelper(context, applicableSkimmers, disabledSkimmers: new HashSet<string>()));
                    analyzeCommandTask.Wait(milliSecondTimeout);

                    if (!analyzeCommandTask.IsCompleted)
                    {
                        Console.WriteLine("File Timed Out after 60 seconds. Moving onto next file.");
                        timer.Stop();
                        fileDataTupleList.Add(Tuple.Create(filePath.Replace(',', ';'), fileSystem.FileInfoLength(filePath) / 1024, (long)milliSecondTimeout));
                        return;
                    }
                }

                long numViolation = logger.ViolationsSeen;
                logger.AnalysisStopped(RuntimeConditions.None);
            }

            timer.Stop();
            fileDataTupleList.Add(Tuple.Create(filePath.Replace(',', ';'), fileSystem.FileInfoLength(filePath) / 1024, timer.ElapsedMilliseconds));
        }

        private int GetNumberOfRegexes(IEnumerable<string> searchDefinitionsPaths)
        {
            int numberOfRegexes = 0;

            foreach (string definitionsFilePath in searchDefinitionsPaths)
            {

                string content = File.ReadAllText(definitionsFilePath);
                SearchDefinitions sdObject = JsonConvert.DeserializeObject<SearchDefinitions>(content);

                foreach (SearchDefinition searchDefinition in sdObject.Definitions)
                {
                    // Add all types of regexes in Definitons or MatchExpressions to hashset
                    if (!string.IsNullOrWhiteSpace(searchDefinition.FileNameAllowRegex))
                    {
                        numberOfRegexes++;
                    }
                    if (!string.IsNullOrWhiteSpace(searchDefinition.FileNameDenyRegex))
                    {
                        numberOfRegexes++;
                    }

                    foreach (MatchExpression matchExpression in searchDefinition.MatchExpressions)
                    {
                        if (!string.IsNullOrWhiteSpace(matchExpression.FileNameAllowRegex))
                        {
                            numberOfRegexes++;
                        }
                        if (!string.IsNullOrWhiteSpace(matchExpression.FileNameDenyRegex))
                        {
                            numberOfRegexes++;
                        }
                        if (!string.IsNullOrWhiteSpace(matchExpression.ContentsRegex))
                        {
                            numberOfRegexes++;
                        }
                        if (matchExpression.IntrafileRegexes != null)
                        {
                            foreach (string intrafileregex in matchExpression.IntrafileRegexes)
                            {
                                if (!string.IsNullOrWhiteSpace(intrafileregex))
                                {
                                    numberOfRegexes++;
                                }
                            }

                        }
                        if (matchExpression.SingleLineRegexes != null)
                        {
                            foreach (string singleLineRegex in matchExpression.SingleLineRegexes)
                            {
                                if (!string.IsNullOrWhiteSpace(singleLineRegex))
                                {
                                    numberOfRegexes++;
                                }
                            }
                        }
                    }
                }

            }

            return numberOfRegexes;
        }
    }
}
