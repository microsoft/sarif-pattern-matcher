// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

using Microsoft.CodeAnalysis.Sarif;
using Microsoft.CodeAnalysis.Sarif.Driver.Sdk;
using Microsoft.CodeAnalysis.SarifPatternMatcher.Strings;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher
{
    public class AnalyzeContext : IAnalysisContext
    {
        public AnalyzeContext()
        {
            // Any file is a candidate for regex-driven search.
            // The actual applicability of a file for a specific
            // search definition is governed by its name/extension.
            IsValidAnalysisTarget = true;
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

        public void Dispose()
        {
        }
    }
}
