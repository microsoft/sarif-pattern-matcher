// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#pragma warning disable SA1117 // Parameters should be on same line or separate line.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.Strings.Interop;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class AnalyzeContext : AnalyzeContextBase
    {
        public static long FilesFilteredBySniffRegex;

        public AnalyzeContext()
        {
            // Any file is a candidate for regex-driven search.
            // The actual applicability of a file for a specific
            // search definition is governed by its name/extension.
            IsValidAnalysisTarget = true;

            // Here is our default name/extension filter.
            GlobalFilePathDenyRegex = "(?i)\\.(?:bmp|dll|exe|gif|jpe?g|lock|pack|png|psd|tar\\.gz|tiff?|ttf|xcf|zip)$";
        }

        public bool RedactSecrets
        {
            get => this.Policy.GetProperty(RedactSecretsProperty);
            set => this.Policy.SetProperty(RedactSecretsProperty, value);
        }

        public IEnumerable<Skimmer<AnalyzeContext>> Skimmers { get; set; }

        public IDictionary<int, string> RollingHashMap { get; set; }

        public override bool AnalysisComplete { get; set; }

        public RegexEngine RegexEngine
        {
            get => this.Policy.GetProperty(RegexEngineProperty);
            set => this.Policy.SetProperty(RegexEngineProperty, value);
        }

        public string SniffRegex
        {
            get => this.Policy.GetProperty(SniffRegexProperty);
            set => this.Policy.SetProperty(SniffRegexProperty, value);
        }

        public bool DynamicValidation
        {
            get => this.Policy.GetProperty(DynamicValidationProperty);
            set => this.Policy.SetProperty(DynamicValidationProperty, value);
        }

        public long MaxMemoryInKilobytes
        {
            get => this.Policy.GetProperty(MaxMemoryInKilobytesProperty);
            set => this.Policy.SetProperty(MaxMemoryInKilobytesProperty, value >= 0 ? value : MaxFileSizeInKilobytesProperty.DefaultValue());
        }

        public bool DisableDynamicValidationCaching
        {
            get => this.Policy.GetProperty(DisableDynamicValidationCachingProperty);
            set => this.Policy.SetProperty(DisableDynamicValidationCachingProperty, value);
        }

        public bool EnhancedReporting
        {
            get => this.Policy.GetProperty(EnhancedReportingProperty);
            set => this.Policy.SetProperty(EnhancedReportingProperty, value);
        }

        public bool Retry
        {
            get => this.Policy.GetProperty(RetryProperty);
            set => this.Policy.SetProperty(RetryProperty, value);
        }

        /// <summary>
        /// Gets or sets a hashset that stores observed fingerprints in the
        /// current scan target. This data is used to prevent firing
        /// multiple instances of the same logically unique apparent
        /// credential.
        /// </summary>
        public HashSet<string> ObservedFingerprintCache { get; set; }

        /// <summary>
        /// Gets or sets a dictionary linking file text with
        /// A String8 that is used to in RE2 searching.
        /// An array of bytes that comprise a buffer used in String8 conversion
        /// An array of integers that comprise a map of UTF8 to UTF16 byte
        /// indices. This data is required to rationalize match segments
        /// when analyzing .NET strings in RE2 (which processes UTF8).
        /// </summary>
        public Dictionary<string, Tuple<String8, byte[], int[]>> TextToRE2DataMap;

        public override void Dispose()
        {
            base.Dispose();

            ObservedFingerprintCache?.Clear();
            ObservedFingerprintCache = null;

            TextToRE2DataMap?.Clear();
            TextToRE2DataMap = null;

            RollingHashMap?.Clear();
            RollingHashMap = null;
        }

        public static PerLanguageOption<RegexEngine> RegexEngineProperty =>
            new PerLanguageOption<RegexEngine>(
                "CoreSettings", nameof(RegexEngine), defaultValue: () => RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? RegexEngine.RE2 : RegexEngine.CachedDotNet,
                "The pattern matching to use for scanning. One of RE2 (Windows default), DotNet, CachedDotNet (Linux default) or IronRE2.");

        public static PerLanguageOption<string> SniffRegexProperty =>
            new PerLanguageOption<string>(
                "CoreSettings", nameof(SniffRegex), defaultValue: () => string.Empty,
                "An optional regex applied to all scan targets as a filter. Files that " +
                "do not match the sniff regex will be skipped at analysis time. ");

        public static PerLanguageOption<bool> EnhancedReportingProperty =>
            new PerLanguageOption<bool>(
                "CoreSettings", nameof(EnhancedReporting), defaultValue: () => false,
                "Specifies whether to enhance findings with asset ownership details.");

        public static PerLanguageOption<bool> DisableDynamicValidationCachingProperty =>
            new PerLanguageOption<bool>(
                "CoreSettings", nameof(DisableDynamicValidationCaching), defaultValue: () => false,
                "Specifies whether to disable dynamic validation caching.");

        public static PerLanguageOption<bool> RetryProperty =>
            new PerLanguageOption<bool>(
                "CoreSettings", nameof(Retry), defaultValue: () => false,
                "Specifies whether to retry dynamic validation in some failure cases.");

        public static PerLanguageOption<bool> RedactSecretsProperty =>
            new PerLanguageOption<bool>(
                "CoreSettings", nameof(RedactSecrets), defaultValue: () => false,
                "Specifies whether to redact secrets from SARIF log.");

        public static PerLanguageOption<bool> DynamicValidationProperty =>
            new PerLanguageOption<bool>(
                "CoreSettings", nameof(DynamicValidation), defaultValue: () => false,
                "Specifies whether to invoke rule dynamic validation, when available.");

        public static PerLanguageOption<long> MaxMemoryInKilobytesProperty =>
            new PerLanguageOption<long>(
                "CoreSettings", nameof(MaxMemoryInKilobytes), defaultValue: () => 5096,
                "An upper bound on the size of the RE2 DFA cache. When the cache size exceeds this " +
                "limit RE2 will fallback to an alternate (much less performant) search mechanism. " +
                "Negative values will be discarded in favor of the default of 5096 KB.");
    }
}
