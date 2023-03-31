// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.Extensions.Logging;
using Microsoft.RE2.Managed;
using Microsoft.Strings.Interop;
using Microsoft.TeamFoundation.SourceControl.WebApi.Legacy;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal class ScanContext
    {
        public ScanContext()
        {
            this.SourceContext = new SourceContext();
        }

        public SourceContext SourceContext { get; set; }
    }

    internal class SourceContext
    {
        public string ResourceName { get; internal set; }
    }

    internal class AdoLogger : IAnalysisLogger
    {
        public bool CatastrophicNotificationObserved { get; set; }

        public long ViolationsSeen { get; set; }

        public FileRegionsCache FileRegionsCache { get; set; }

        public void AnalysisStarted() { }

        public void AnalysisStopped(RuntimeConditions runtimeConditions) { }

        public void AnalyzingTarget(IAnalysisContext context) { }

        public void TargetAnalyzed(IAnalysisContext context) { }

        public void Log(ReportingDescriptor rule, Result result, int? extensionIndex)
        {
            // Build your ADO data contract here
            ViolationsSeen++;
        }

        public void LogConfigurationNotification(Notification notification) { }

        public void LogToolNotification(Notification notification, ReportingDescriptor _)
        {
            if (notification.Level == FailureLevel.Error)
            {
                CatastrophicNotificationObserved = true;
            }
        }
    }

    internal class StressCommand : CommandBase
    {
        private static int filesScanned = 0;
        private readonly List<Tuple<string, long, long, double, double>> fileDataTupleList = new List<Tuple<string, long, long, double, double>>();
        private readonly IFileSystem fileSystem = Sarif.FileSystem.Instance;

        private IEnumerable<string> s_configurationFiles;

        public int Run(StressOptions options)
        {
            switch (options.Scenario)
            {
                case StressScenario.Statelessness:
                {
                    RunStatelessStressScenario(options);
                    break;
                }

                case StressScenario.RE2Timing:
                {
                    RunRE2TimingScenario(options);
                    break;
                }

                case StressScenario.SingleThreadedTelemetry:
                {
                    // For simplicity, I added the timing tests to stress command
                    // It runs with a folder passed in as the file.
                    RunSingleThreadedTelemetry(options);
                    break;
                }

                case StressScenario.MultiThreadedTelemetry:
                {
                    RunMultiThreadedTelemetry(options);
                    break;
                }
            }

            return SUCCESS;
        }

        private void RunRE2TimingScenario(StressOptions options)
        {
            string filePath = options.InputFilePath;

            FlexString resourceContent = File.ReadAllText(filePath);

            var regexList = new List<string> { "a", "abc", "hulonhulonhulon", "(?:^|[^0-9A-Za-z_])(ghp_[\\w]{36})(?:[^0-9A-Za-z_]|$)", "(?P<secret>a)", "(?P<secret>abc)", "(?P<secret>hulonhulonhulon)", "(?:^|[^0-9A-Za-z_])(?P<secret>ghp_[\\w]{36})(?:[^0-9A-Za-z_]|$)" };

            var sb = new StringBuilder();

            int iterations = options.Iterations;

            String8 expression8 = String8.Empty;
            var textToRE2DataMap = new Dictionary<string, Tuple<String8, byte[], int[]>>();
            foreach (string regex in regexList)
            {
                // Current Match
                var currentRegexSW = Stopwatch.StartNew();

                // Call from line 969 of SearchSkimmers.cs
                int matchesCount = 0;
                for (int i = 0; i < iterations; i++)
                {
                    ((RE2Regex)RE2Regex.Instance).Matches(regex, resourceContent, out List<Dictionary<string, FlexMatch>> matches, ref textToRE2DataMap, -1);
                    matchesCount = matches.Count;
                }

                currentRegexSW.Stop();

                // Legacy Match
                var legacyRegexSW = Stopwatch.StartNew();

                // call from line 642 of PatternMatcher.cs

                int legacyMatchesCount = 0;
                for (int i = 0; i < iterations; i++)
                {
                    legacyMatchesCount = 0;
                    foreach (FlexMatch match in RE2Regex.Instance.Matches(resourceContent, regex, RegexDefaults.DefaultOptionsCaseSensitive))
                    {
                        legacyMatchesCount++;
                    }
                }

                legacyRegexSW.Stop();
                sb.AppendLine($"For regex: \"{regex}\", Legacy: {legacyRegexSW.ElapsedMilliseconds}ms, matches: {legacyMatchesCount} \tCurrent: {currentRegexSW.ElapsedMilliseconds}ms, matches: {matchesCount}");
            }

            Console.WriteLine(sb.ToString());
        }

        private void RunStatelessStressScenario(StressOptions options)
        {
            IFileSystem fileSystem = Sarif.FileSystem.Instance;
            s_configurationFiles = new string[] { options.InputFilePath };
            var tool = Tool.CreateFromAssemblyData();
            ISet<Skimmer<AnalyzeContext>> skimmers = AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(fileSystem, s_configurationFiles, tool);

            var logger = new AdoLogger();
            var scanContext = new ScanContext();
            string resourceContent = Encoding.UTF8.GetString(Convert.FromBase64String(TestContents));
            var disabledSkimmers = new HashSet<string>();

            scanContext.SourceContext.ResourceName = "TestFile.cs";

            // Make sure that file content is unique to flush out
            // contents-specific caching issues (for line indexes).
            resourceContent += Guid.NewGuid().ToString();

            for (int i = 0; i < 10000000; i++)
            {
                skimmers ??= AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(fileSystem, s_configurationFiles, tool);

                var target = new EnumeratedArtifact(FileSystem)
                {
                    Uri = new Uri(scanContext.SourceContext.ResourceName, UriKind.RelativeOrAbsolute),
                    Contents = resourceContent,
                };

                var context = new AnalyzeContext
                {
                    CurrentTarget = target,
                    Logger = logger,
                };

                using (context)
                {
                    disabledSkimmers.Clear();
                    AnalyzeCommand.AnalyzeTargetHelper(context, skimmers, disabledSkimmers);
                    Console.WriteLine($"Violations observed: {logger.ViolationsSeen}");
                }

                if (logger.CatastrophicNotificationObserved)
                {
                    skimmers = null;
                }
            }
        }

        private void RunSingleThreadedTelemetry(StressOptions options)
        {
            Console.WriteLine("Starting Timing Tests - Current Tool!");

            List<string> filesToSearch = GetWhatFilesToSearch(options);

            var tool = Tool.CreateFromAssemblyData();
            ISet<Skimmer<AnalyzeContext>> skimmers = AnalyzeCommand.CreateSkimmersFromDefinitionsFiles(fileSystem, options.SearchDefinitionsPaths, tool);

            var totalRunTimer = new Stopwatch();
            totalRunTimer.Start();
            foreach (string filePath in filesToSearch)
            {
                Console.WriteLine($"Scanning file: {filesScanned} of {filesToSearch.Count}");
                TimeScanFileWithSkimmers(filePath, skimmers);
                filesScanned++;
            }

            totalRunTimer.Stop();
            ExportSizeAndExecutionTime(totalRunTimer.Elapsed, options.CSVFilePath);

            Console.WriteLine($"Timing Tests Finished. Total Runtime: {totalRunTimer.Elapsed}");
        }

        private void RunMultiThreadedTelemetry(StressOptions options)
        {
            var analyzeOptions = new AnalyzeOptions()
            {
                TargetFileSpecifiers = new List<string> { options.InputFilePath },
                Recurse = true,
                OutputFilePath = options.OutputFilePath,
                OutputFileOptions = new List<FilePersistenceOptions>() { FilePersistenceOptions.ForceOverwrite },
                Level = new FailureLevelSet(new[] { FailureLevel.Error, FailureLevel.Warning, FailureLevel.Note }),
                Kind = new ResultKindSet(new[] { ResultKind.Fail }),
                MaxFileSizeInKilobytes = 99999999,
                Threads = Environment.ProcessorCount - 1,
                PluginFilePaths = options.SearchDefinitionsPaths,
            };

            new AnalyzeCommand().Run(analyzeOptions);
        }

        private List<string> GetWhatFilesToSearch(StressOptions options)
        {
            // Get a list of files to search
            string folderToSearch = options.InputFilePath;
            var filesToSearch = new List<string>();

            filesToSearch.AddRange(Directory.GetFiles(folderToSearch, "*", SearchOption.AllDirectories).ToList<string>());

            return filesToSearch;
        }

        private void ExportSizeAndExecutionTime(TimeSpan totalRunTime, string outputFilePath)
        {
            // output Tuple list to csv in 3 columns
            var sb = new StringBuilder($"Filename, File Size in KB, Runtime in ms, %-CPU Utilization, Peak Mem (MB), Total RunTime: {totalRunTime}{Environment.NewLine}");

            foreach (Tuple<string, long, long, double, double> runData in fileDataTupleList)
            {
                sb.AppendLine($"{runData.Item1}, {runData.Item2}, {runData.Item3}, {runData.Item4}, {runData.Item5}");
            }

            File.WriteAllText(outputFilePath, sb.ToString());
        }

        private void TimeScanFileWithSkimmers(string filePath, ISet<Skimmer<AnalyzeContext>> skimmers)
        {
            string resourceContent = fileSystem.FileReadAllText(filePath);
            long fileSizeInBytes = fileSystem.FileInfoLength(filePath);
            Process.GetCurrentProcess().Refresh();

            var timer = new Stopwatch();
            TimeSpan startCpu = Process.GetCurrentProcess().TotalProcessorTime;

            timer.Start();

            // Critical Section Being Timed
            {
                var logger = new AdoLogger();

                var target = new EnumeratedArtifact(FileSystem)
                {
                    Uri = new Uri(filePath, UriKind.RelativeOrAbsolute),
                    Contents = resourceContent,
                };

                // Set up Context
                var context = new AnalyzeContext
                {
                    CurrentTarget = target,
                    Logger = logger,
                };

                var disabledSkimmers = new HashSet<string>();
                // how fast is this? should be fast!
                IEnumerable<Skimmer<AnalyzeContext>> applicableSkimmers = AnalyzeCommand.DetermineApplicabilityForTargetHelper(context, skimmers, disabledSkimmers);

                logger.AnalysisStarted();

                // Run analyze
                using (context)
                {

                    AnalyzeCommand.AnalyzeTargetHelper(context, applicableSkimmers, disabledSkimmers: new HashSet<string>());
                }

                long numViolation = logger.ViolationsSeen;
                logger.AnalysisStopped(RuntimeConditions.None);
            }

            TimeSpan endCpu = Process.GetCurrentProcess().TotalProcessorTime;
            timer.Stop();

            double cpuUtilization = 100 * (endCpu.TotalMilliseconds - startCpu.TotalMilliseconds) / (Environment.ProcessorCount * timer.ElapsedMilliseconds);
            fileDataTupleList.Add(Tuple.Create(filePath.Replace(',', ';'), fileSystem.FileInfoLength(filePath) / 1024, timer.ElapsedMilliseconds, cpuUtilization, (double)Process.GetCurrentProcess().PeakVirtualMemorySize64 / 1000000));
        }

        private readonly string TestContents = "dXNpbmcgU3lzdGVtOwp1c2luZyBTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYzsKCm5hbWVzcGFjZSBNaWNyb3NvZnQuQ29kZUFuYWx5c2lzLlNhcmlmLlBhdHRlcm5NYXRjaGVyLlRlc3QKewogICAgLy8vIDxzdW1tYXJ5PgogICAgLy8vIFRoaXMgY2xhc3MgY29udGFpbnMgcHJlYWxsb2NhdGVkIGtleXMgZm9yIHRlc3RpbmcuIEV2ZXJ5IGtleSBtdXN0IGJlIHByZWZpeGVkCiAgICAvLy8gd2l0aCB0aGUgbmFtZSBvZiB0aGUgc2VjcmV0IGtpbmQgKHdoaWNoIGl0c2VsZiBpcyB0aGUgcHJlZml4IGZvciBldmVyeSB2YWxpZGF0b3IpLgogICAgLy8vIDwvc3VtbWFyeT4KICAgIGludGVybmFsIGNsYXNzIFByZWFsbG9jYXRlZElkZW50aWZhYmxlVGVzdFNlY3JldHMKICAgIHsKICAgICAgICBwdWJsaWMgY29uc3Qgc3RyaW5nIEFkb1BhdCA9ICJteGk0Y28ya2RsbHlpYWUzaXdtNTc0NXBhcjI0MnFzZGJhd25rYWxxb3pibHJkcDJpenBxIjsKCiAgICAgICAgLy8gVGhlIEF6dXJlIENhY2hlIGdlbmVyYXRlZCB0b2tlbnMgaGF2ZSBhbiBvZGQgYmVoYXZpb3JzLCB3aGljaCBpcyB0byBlbGltaW5hdGUgc3BlY2lhbCBjaGFyYWN0ZXJzCiAgICAgICAgLy8gZnJvbSB0b2tlbnMgYnkgcmVwbGFjaW5nIHRoZW0gd2l0aCAnUCcgKGZvciB0aGUgcGx1cyBzaWduKSBhbmQgJ1MnIGZvciB0aGUgZm9yd2FyZCBzbGFzaC4gVGhpcwogICAgICAgIC8vIGFwcHJvYWNoIHdhcyB0YWtlbiB0byBoZWxwIG1pbmltaXplIGNoYW5nZXMgdG8gdGhlIHJlc291cmNlIHByb3ZpZGVyIGNvZGUuIEEgYmV0dGVyIGFwcHJvYWNoIHdvdWxkCiAgICAgICAgLy8gaGF2ZSBiZWVuIHRvIHNpbXBseSBnZW5lcmF0ZSBrZXlzIHVudGlsIHRoZSBBUEkgcHJvZHVjZWQgYSB0b2tlbiB3aXRoIG5vIGZvcmJpZGRlbiBjaGFycyBpbiB0aGUKICAgICAgICAvLyBjaGVja3N1bS4gVGhpcyBhcHByb2FjaCB3YXMgdGFrZW4gaW4gbGF0ZXIgcmVzb3VyY2UgcHJvdmlkZXJzIChBQ1Igd2FzIGEgdmVyeSBlYXJseSBpbXBsZW1lbnRhdGlvbikuCiAgICAgICAgcHVibGljIGNvbnN0IHN0cmluZyBBenVyZUNhY2hlRm9yUmVkaXNJZGVudGlmaWFibGVLZXkgPSAiY1RoSVlMQ0Q2SDdMcldyTkhRanhoYVNCdTQyS2VTekdsQXpDYU5RSlhkQT0iOwogICAgICAgIHB1YmxpYyBjb25zdCBzdHJpbmcgQXp1cmVDYWNoZUZvclJlZGlzSW50ZXJuYWxJZGVudGlmaWFibGVLZXkgPSAiZmJRcVN1MjE2TXZ3TmFxdVNxcEk4TVYwaHFsVVBnR0NoT1kxOWRjOXhEUk1BekNhaXhDWWJRIjsKICAgICAgICBwdWJsaWMgY29uc3Qgc3RyaW5nIEF6dXJlQ2FjaGVGb3JSZWRpc0lkZW50aWZpYWJsZUtleUNoZWNrc3VtSGFzU2xhc2ggPSAickt5QmNqdG14dzBVT0wyV2c3elVHYVViN1RlcWxpSzhhQXpDYU00RjRiTT0iOwogICAgICAgIHB1YmxpYyBjb25zdCBzdHJpbmcgQXp1cmVDYWNoZUZvclJlZGlzSWRlbnRpZmlhYmxlS2V5Q2hlY2tzdW1IYXNQbHVzU2lnbiA9ICJaNzdnSEJrYXpWUkZ1ZHR1S3VzUFd1TE1ONzdKdTJPVUtBekNhTFBRTnN3PSI7CgogICAgICAgIHB1YmxpYyBjb25zdCBzdHJpbmcgQWFkQ2xpZW50QXBwSWRlbnRpZmlhYmxlQ3JlZGVudGlhbHNMZWdhY3kgID0gIjVZOTdRfmsxZ2ZzRlVhSS5salplTHpNR2Q0OEVibDc3VkVjNXYiOwogICAgICAgIHB1YmxpYyBjb25zdCBzdHJpbmcgQWFkQ2xpZW50QXBwSWRlbnRpZmlhYmxlQ3JlZGVudGlhbHNDdXJyZW50ID0gIkEwNDhRfmc2LU4tMDZfMS0xfmY2LjktN004MV84ZHUwLm9+X09jVS4iOwoKICAgICAgICBwdWJsaWMgY29uc3Qgc3RyaW5nIEF6dXJlQ29zbW9zREJJZGVudGlmaWFibGVLZXlQcmltYXJ5TWFzdGVyS2V5ID0gInp1N3Y2VlljcFJPa08xaXBHQUVpcm9Oc2M0R0xCMDdIZkxYZzRzQTlSOFI4Q0pPZzRrWjJNcjgzUGQyRzRYemZwTWo3d1J2aGh6YnNBQ0RicDlCMmp3PT0iOwogICAgICAgIHB1YmxpYyBjb25zdCBzdHJpbmcgQXp1cmVDb3Ntb3NEQklkZW50aWZpYWJsZUtleVNlY29uZGFyeU1hc3RlcktleSA9ICJnR2lpcW1pOE43QW00U3lPdUN0NDNQVVdkSnN3YnBiVXZEQjRod3lDZzBaTVZ4VUJaYlFRbE12YUFWakxvdlRWWUk1STVEc0s4WTViQUNEYk44YklMdz09IjsKICAgICAgICBwdWJsaWMgY29uc3Qgc3RyaW5nIEF6dXJlQ29zbW9zREJJZGVudGlmaWFibGVLZXlQcmltYXJ5UmVhZG9ubHlNYXN0ZXJLZXkgPSAiOU9pU2FVcG9aUGJiYTAzVThmQjh1ZThBalk1SkdCT05TVjU0cmhGN3hGd3ZLSkoxUHp1N0JUY2ZzeWpreW4yRW5LWHZNZzk5V1E1VEFDRGI5MjAycWc9PSI7CiAgICAgICAgcHVibGljIGNvbnN0IHN0cmluZyBBenVyZUNvc21vc0RCSWRlbnRpZmlhYmxlS2V5U2Vjb25kYXJ5UmVhZG9ubHlNYXN0ZXJLZXkgPSAiRDMzZDdKdTdhTXpValVQTEhPaTlRMkxXNnIxWTVISXJ0YjZkeWw4Q0R2SWlaOFdBUXZ3c28yWXZ1R0t0bzJFRm9lcEFRWXZTWUFYUEFDRGJkRlpveWc9PSI7CiAgICAgICAgcHVibGljIGNvbnN0IHN0cmluZyBBenVyZUNvc21vc0RCSW50ZXJuYWxJZGVudGlmaWFibGVLZXlQcmltYXJ5U3lzdGVtS2V5QWxsID0gIkhZd3BKbDM2aVRKdGZyZlJwOWNwb1B4aUtJMVJzWEhPOUxzc3ZmalRvYU9EM2IrbW4rNjZkTHUwdjBnUmRqQ1pkcXNYWVJ4dW5GYmdBQ0RiRHBTWjVBPT0iOwogICAgICAgIHB1YmxpYyBjb25zdCBzdHJpbmcgQXp1cmVDb3Ntb3NEQkludGVybmFsSWRlbnRpZmlhYmxlS2V5U2Vjb25kYXJ5U3lzdGVtS2V5QWxsID0gIkxLOUVSbnVsTVpVbkdjNGpHQVhHRU9YQkZ3MGdOdlExMy9wWEo1TmZqYVVtVnd2M0ZsZXVuSDVWTkZnd3dTMEFTQ1ZpWStBN2xUbUdBQ0RiRjJXTTJRPT0iOwogICAgICAgIHB1YmxpYyBjb25zdCBzdHJpbmcgQXp1cmVDb3Ntb3NEQkludGVybmFsSWRlbnRpZmlhYmxlS2V5UHJpbWFyeVN5c3RlbUtleVJlYWRXcml0ZSA9ICJWd3hxejlRemtQUFdiV3VTeStVYTlQN0RETTVvakNzZU5ONmk5UGZCMFpGTnN5VWtZeGN3SWNBUEhEZi95ZUpmdnA5aE4rZDQ4Ylg5QUNEYnFvQ3I0dz09IjsKICAgICAgICBwdWJsaWMgY29uc3Qgc3RyaW5nIEF6dXJlQ29zbW9zREJJbnRlcm5hbElkZW50aWZpYWJsZUtleVNlY29uZGFyeVN5c3RlbUtleVJlYWRXcml0ZSA9ICJLd2FMWUpja0FNQ0lUU2Jnb3YzdjFBUTRRdnZaUm80aTU1c3ZSL3ljNWdhdCtQbENrWmNrSVlzNG9XM3RCdWcwZHVaM1N1ejRSa3hYQUNEYlQ3ZlZZdz09IjsKICAgICAgICBwdWJsaWMgY29uc3Qgc3RyaW5nIEF6dXJlQ29zbW9zREJJbnRlcm5hbElkZW50aWZpYWJsZUtleVByaW1hcnlTeXN0ZW1LZXlSZWFkT25seSA9ICJ3UE9aMFR1Ri9BOW1XbDI4ZlNnVURReHdhZkcvM3JXRTFIUnkvM1JRZHVxaFR4QisrZzZjNTh6VStYci95OHpMUENWb2IzSEVDWWtRQUNEYjR5bytIQT09IjsKICAgICAgICBwdWJsaWMgY29uc3Qgc3RyaW5nIEF6dXJlQ29zbW9zREJJbnRlcm5hbElkZW50aWZpYWJsZUtleVNlY29uZGFyeVN5c3RlbUtleVJlYWRPbmx5ID0gImNZM0hOZnRsajFkREkwcGxNaU02VW43a3NQYmo5VmVMWERxcTZETTNYTDgrNDVmUTM1U010cmRodEtsVytNVHJpc3lTRTZJU0pWa3BBQ0RiUVM5cFhRPT0iOwogICAgICAgIHB1YmxpYyBjb25zdCBzdHJpbmcgQXp1cmVDb3Ntb3NEQkludGVybmFsSWRlbnRpZmlhYmxlS2V5UmVzb3VyY2VLZXlTZWVkID0gInlvaVIrcUVaVm5RRjU1S09mZkRVMXZIUFZaU3dmamhjL0FDRGJDbHZhTVk9IjsKICAgICAgICBwdWJsaWMgY29uc3Qgc3RyaW5nIEF6dXJlQ29zbW9zREJJbnRlcm5hbElkZW50aWZpYWJsZUtleURhdGFFbmNyeXB0aW9uS2V5ID0gIkkwWkZCcktJaHNYTG5XenppWUJrZjUrNThmN05NeHhGekFDRGJEV3FJZmM9IjsKCiAgICAgICAgcHVibGljIGNvbnN0IHN0cmluZyBBenVyZUZ1bmN0aW9uSWRlbnRpZmlhYmxlS2V5TWFzdGVyS2V5ID0gImxLNWpYMmQ1TnNoR3JpUXg4MkVNcklFcko4dDVQdVFSZ2pwdkdYVmNPLWxGQXpGdVNyU2o2Zz09IjsKICAgICAgICBwdWJsaWMgY29uc3Qgc3RyaW5nIEF6dXJlRnVuY3Rpb25JZGVudGlmaWFibGVLZXlTeXN0ZW1LZXkgPSAiakRTdXhsSWZZYVJkY0U1ZjlRVno1LWZFdmpwY1R2bmg2TUYwSDM1dlpuRk5BekZ1TUx5ZEVBPT0iOwogICAgICAgIHB1YmxpYyBjb25zdCBzdHJpbmcgQXp1cmVGdW5jdGlvbklkZW50aWZpYWJsZUtleUZ1bmN0aW9uS2V5ID0gIlllMmtOYnVweHFJdmdEaG5NTDFfT2ZmYndsdXNZaDRFWkg4WjFuSE85Z2pJQXpGdW01bmprdz09IjsKCiAgICAgICAgcHVibGljIGNvbnN0IHN0cmluZyBBenVyZU1MSWRlbnRpZmlhYmxlSW50ZXJuYWxTZXJ2aWNlUHJpbmNpcGFsQ3JlZGVudGlhbHNDdXJyZW50ID0gImsxR1AxR0Y0S2hLQ3VWWWhFQWhpeHVHN2hqQ1Q3eFFsRTFudlJhRVAxZDVkYzMvQU03QWpaL05GIjsKICAgICAgICBwdWJsaWMgY29uc3Qgc3RyaW5nIEF6dXJlTUxXZWJTZXJ2aWNlQ2xhc3NpY0lkZW50aWZpYWJsZUtleSA9ICI5RUR2VS9ya3NJRnBGeGNSVTFya1diT254Y2Vzck9xL3hTcFhRSWc4QTZ1VVFXbERRRHlrSU5GVGlRcDVsZzZ2dHlKOVNBd0ZnYmR6K0FNQ2RxN3BDQT09IjsKCiAgICAgICAgcHVibGljIGNvbnN0IHN0cmluZyBBenVyZVN0b3JhZ2VBY2NvdW50SWRlbnRpZmlhYmxlQ3JlZGVudGlhbHMgPSAiVTFpbVhXMGFjQTVRUnRua0t1VzE0UVBTQy9GMUpGUzltT2pkOE55L011YWI0MkNWa0k4RzAvamE3dU0xM0dsZmlTOHBwNGMva3pZcCtBU3R2QmpTMXc9PSI7CiAgICAgICAgcHVibGljIGNvbnN0IHN0cmluZyBBenVyZVN0b3JhZ2VBY2NvdW50SW50ZXJuYWxJZGVudGlmaWFibGVDcmVkZW50aWFsc0VuY3J5cHRlZDMyQnl0ZXMgPSAiS1RyWHhBWjhnakhGemxPRUJ5RUZEem9YdGtMYXR4anpyK0FTdERiSU9XZz0iOwogICAgICAgIHB1YmxpYyBjb25zdCBzdHJpbmcgQXp1cmVTdG9yYWdlQWNjb3VudEludGVybmFsSWRlbnRpZmlhYmxlQ3JlZGVudGlhbHNLZXJiZXJvcyA9ICJPdVQ5eGRJZGtwZTZrR1ZqSm9zS0NmUlRaSlF1cGR5MnNaTEwvRjVoUFNhQ1VVV3RpNmxrMVRJbjFQNFpjbS81aVgwczFqWUNNUFBuK0FTdEVPdTl3dz09IjsKICAgICAgICBwdWJsaWMgY29uc3Qgc3RyaW5nIEF6dXJlU3RvcmFnZUFjY291bnRJbnRlcm5hbElkZW50aWZpYWJsZUNyZWRlbnRpYWxzRW5jcnlwdGVkNjRCeXRlcyA9ICJBMVkzUW1Kb0hFMURNU0wyTDJMZWpici94ZEhPWEdBZVJpMm1UdkN3OHExUUJsbm16MUJYOEFlaFVndGlqZ1ljUEx1N3NZUFVmMlV0K0FTdGN6dHozQT09IjsKCiAgICAgICAgcHVibGljIGNvbnN0IHN0cmluZyBBenVyZVNlYXJjaElkZW50aWZpYWJsZUFkbWluS2V5ID0gIlZMY0dEM2JPNFBTUGFLczRzS2lTdlpDYWRQbjFoMHhWcng0Qm1UQmx1WUF6U2VEZ0IzeDEiOwogICAgICAgIHB1YmxpYyBjb25zdCBzdHJpbmcgQXp1cmVTZWFyY2hJZGVudGlmaWFibGVRdWVyeUtleSA9ICJFaGZqNUVrSHJMQXh4anNpbzZuT3ZMak13cThvYndqUTU0aXJDZmI4MGxBelNlREIxSXhKIjsKICAgICAgICBwdWJsaWMgY29uc3Qgc3RyaW5nIEF6dXJlU2VhcmNoSW50ZXJuYWxJZGVudGlmaWFibGVBZG1pbktleSA9ICJzaHgzR2VmMEVSVzl3YmtqQUNPMzNJY0s5dkJkcVdhUnZoUDYzcE5WVVJBelNlRHZiRDZOIjsKCiAgICAgICAgcHVibGljIGNvbnN0IHN0cmluZyBHaXRIdWJQYXQgPSAiZ2hwX2lKeHl1NEprU2FWVVMxRVZCbWFvazBZQWw1NnVMcjNpcFk3QiI7CgogICAgICAgIHB1YmxpYyBjb25zdCBzdHJpbmcgTnBtQXV0aG9ySWRlbnRpZmlhYmxlVG9rZW4gPSAibnBtX2VWdklESVRNMnFJMTc3RjRab0FJWG9jb3lJblNYNzJzZkRNRiI7CgogICAgICAgIHB1YmxpYyBjb25zdCBzdHJpbmcgT2ZmaWNlSW5jb21pbmdXZWJob29rVXJsID0gImh0dHBzOi8vbWljcm9zb2Z0LndlYmhvb2sub2ZmaWNlLmNvbS93ZWJob29rYjIvNzlhMWVmY2UtZDU4NS00ZGZmLWE2ZGUtY2QwNjg1ZGVkYjVkQDcyZjk4OGJmLTg2ZjEtNDFhZi05MWFiLTJkN2NkMDExZGI0Ny9JbmNvbWluZ1dlYmhvb2svMWJmZTE4NmM4MTVhNGUwMjgxZjJiNzRlNTU0NDJjYzgvMzAxNjViMDYtOGNjMi00OWRhLTkzOGQtZTAwNjU4Y2NjODZhIjsKICAgIH0KfQ==";
    }
}
