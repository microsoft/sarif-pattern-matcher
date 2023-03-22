// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using CommandLine;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    [Verb("analyze")]
    public class AnalyzeOptions : AnalyzeOptionsBase
    {
        [Option(
            "vcp",
            Separator = ';',
            HelpText = "A serialized JSON version control details object to persist to the output file.")]
        public string VersionControlProvenance { get; set; }

        [Option(
            "dynamic-validation",
            HelpText = "Enable dynamic validations, if any (may compromise " +
                       "performance and/or result in calls across the network).")]
        public bool? DynamicValidation { get; internal set; }

        [Option(
            "deny-regex",
            HelpText = "A regular expression used to suppress scanning for any file or directory path that matches the regex.")]
        public string FileNameDenyRegex { get; internal set; }

        [Option(
            "disable-dynamic-validation-caching",
            HelpText = "Disable caching from dynamic validation.")]
        public bool? DisableDynamicValidationCaching { get; internal set; }

        [Option(
            "enhanced-reporting",
            HelpText = "Enable enhanced reporting provided by dynamic validators (when --dynamic-validation is also enabled).")]
        public bool? EnhancedReporting { get; internal set; }

        [Option(
            "retry",
            HelpText = "Enable retry connection if enabled.")]
        public bool? Retry { get; set; }

        [Option(
            "max-memory-in-kb",
            HelpText = "The maximum memory (in kilobytes) that can be used for RE2.",
            Default = -1)]
        public long MaxMemoryInKilobytes { get; internal set; }

        [Option(
            "redact-secrets",
            HelpText = "Redact sensitive credential components from log files.")]
        public bool? RedactSecrets { get; internal set; }
    }
}
