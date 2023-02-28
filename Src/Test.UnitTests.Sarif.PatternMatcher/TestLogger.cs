// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class TestLogger : IAnalysisLogger
    {
        public IList<Notification> ConfigurationNotifications { get; set; }
        public IList<Notification> ToolNotifications { get; set; }
        public ISet<ReportingDescriptor> Rules { get; set; }
        public IList<Result> Results { get; set; }

        public bool NoNotificationsFired
        {
            get => ConfigurationNotifications == null && ToolNotifications == null;
        }

        public bool NothingFired
        {
            get => Results == null && NoNotificationsFired;
        }

        public void AnalysisStarted()
        {
        }

        public void AnalysisStopped(RuntimeConditions runtimeConditions)
        {
        }

        public void AnalyzingTarget(IAnalysisContext context)
        {
        }

        public void Log(ReportingDescriptor rule, Result result, int? extensionIndex)
        {
            Results ??= new List<Result>();
            Results.Add(result);

            Rules ??= new HashSet<ReportingDescriptor>(ReportingDescriptor.ValueComparer);
            Rules.Add(rule);
        }

        public void LogConfigurationNotification(Notification notification)
        {
            ConfigurationNotifications ??= new List<Notification>();
            ConfigurationNotifications.Add(notification);
        }

        public void LogToolNotification(Notification notification, ReportingDescriptor _)
        {
            ToolNotifications ??= new List<Notification>();
            ToolNotifications.Add(notification);
        }
    }
}
