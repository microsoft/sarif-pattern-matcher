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

            foreach (string filePath in filesToSearch)
            {
                Console.WriteLine($"Scanning file: {filesScanned} of {filesToSearch.Count}");
                TimeScanFileWithSkimmers(filePath, skimmers);
                filesScanned++;
            }

            ExportSizeAndExecutionTime();
            return SUCCESS;
        }

        public void ExportSizeAndExecutionTime()
        {
            // output Tuple list to csv in 3 columns
            var sb = new StringBuilder($"Filename, File Size in KB, Runtime in ms{Environment.NewLine}");

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
                    //AnalyzeCommand.AnalyzeTargetHelper(context, applicableSkimmers, disabledSkimmers: new HashSet<string>());

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
    }
}
