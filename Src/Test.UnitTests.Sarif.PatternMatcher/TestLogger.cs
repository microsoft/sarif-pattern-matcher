﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class TestLogger : IAnalysisLogger
    {
        public IList<Result> Results { get; set; }

        public void AnalysisStarted()
        {
        }

        public void AnalysisStopped(RuntimeConditions runtimeConditions)
        {
        }

        public void AnalyzingTarget(IAnalysisContext context)
        {
        }

        public void Log(ReportingDescriptor rule, Result result)
        {
            Results ??= new List<Result>();
            Results.Add(result);
        }

        public void LogConfigurationNotification(Notification notification)
        {
        }

        public void LogToolNotification(Notification notification)
        {
        }
    }
}
