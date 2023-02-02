// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.Strings.Interop;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class AnalyzeContext : AnalyzeContextBase
    {
        private FlexString fileContents;

        public AnalyzeContext()
        {
            // Any file is a candidate for regex-driven search.
            // The actual applicability of a file for a specific
            // search definition is governed by its name/extension.
            FileRegionsCache = null;
            IsValidAnalysisTarget = true;
            FileSystem = new FileSystem();
            Policy = new PropertiesDictionary();
            ObservedFingerprintCache = new HashSet<string>();
            TextToRE2DataMap = new Dictionary<string, Tuple<String8, byte[], int[]>>();
        }

        public bool RedactSecrets { get; set; }

        public IEnumerable<Skimmer<AnalyzeContext>> Skimmers { get; set; }

        public IDictionary<int, string> RollingHashMap { get; set; }

        // TODO delete this entirely.
        public FlexString FileContents
        {
            get => this.fileContents ?? this.CurrentTarget?.Contents;
            set => this.fileContents = value;
        }

        public override bool AnalysisComplete { get; set; }

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

        public string GlobalFileDenyRegex { get; set; }

        public bool DisableDynamicValidationCaching { get; set; }

        public bool EnhancedReporting { get; set; }

        public bool Retry { get; set; }

        public FileRegionsCache FileRegionsCache { get; set; }

        /// <summary>
        /// Gets a hashset that stores observed fingerprints in the
        /// current scan target. This data is used to prevent firing
        /// multiple instances of the same logically unique apparent
        /// credential.
        /// </summary>
        public HashSet<string> ObservedFingerprintCache { get; private set; }

        /// <summary>
        /// Gets or sets a dictionary linking file text with
        /// A String8 that is used to in RE2 searching
        /// An array of bytes that comprise a buffer used in String8 conversion
        /// An array of integers that comprise a map of UTF8 to UTF16 byte
        /// indices. This data is required to rationalize match segments
        /// when analyzing .NET strings in RE2 (which processes UTF8).
        /// </summary>
        public Dictionary<string, Tuple<String8, byte[], int[]>> TextToRE2DataMap;

        public override void Dispose()
        {
            FileRegionsCache?.ClearCache();
            FileRegionsCache = null;

            ObservedFingerprintCache?.Clear();
            ObservedFingerprintCache = null;

            TextToRE2DataMap?.Clear();
            TextToRE2DataMap = null;
        }

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
