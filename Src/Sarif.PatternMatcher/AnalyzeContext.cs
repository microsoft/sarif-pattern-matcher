// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.Strings.Interop;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class AnalyzeContext : IAnalysisContext
    {
        public AnalyzeContext()
        {
            // Any file is a candidate for regex-driven search.
            // The actual applicability of a file for a specific
            // search definition is governed by its name/extension.
            IsValidAnalysisTarget = true;
            ObservedFingerprintCache = new HashSet<string>();
            FileRegionsCache = new FileRegionsCache();
        }

        public Exception TargetLoadException { get; set; }

        public bool IsValidAnalysisTarget { get; set; }

        public IAnalysisLogger Logger { get; set; }

        public ReportingDescriptor Rule { get; set; }

        public PropertiesDictionary Policy { get; set; }

        public string MimeType { get; set; }

        public HashData Hashes { get; set; }

        public RuntimeConditions RuntimeErrors { get; set; }

        public Uri TargetUri { get; set; }

        public FlexString FileContents { get; set; }

        public bool AnalysisComplete { get; set; }

        public DefaultTraces Traces { get; set; }

        public bool DynamicValidation { get; set; }

        public string GlobalFileDenyRegex { get; set; }

        public int MaxFileSizeInKilobytes { get; set; } = 10000;

        public bool DisableDynamicValidationCaching { get; set; }

        public bool EnhancedReporting { get; set; }

        public bool Retry { get; set; }

        public long MaxMemoryInKilobytes { get; set; } = -1;

        public FileRegionsCache FileRegionsCache { get; set; }

        public IEnumerable<Skimmer<AnalyzeContext>> Skimmers { get; set; }

        /// <summary>
        /// Gets a hashset that stores observed fingerprints in the
        /// current scan target. This data is used to prevent firing
        /// multiple instances of the same logically unique apparent
        /// credential.
        /// </summary>
        public HashSet<string> ObservedFingerprintCache { get; private set; }

        /// <summary>
        /// Gets or sets flags that specify how region data should be
        /// constructed (for example if comprehensive regions properties
        /// should be computed).
        /// </summary>
        public OptionallyEmittedData DataToInsert { get; set; }

        public void Dispose()
        {
            FileRegionsCache?.ClearCache();
            FileRegionsCache = null;

            ObservedFingerprintCache?.Clear();
            ObservedFingerprintCache = null;
        }
    }
}
