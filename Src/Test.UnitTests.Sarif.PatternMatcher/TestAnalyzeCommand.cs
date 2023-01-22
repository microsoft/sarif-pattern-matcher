// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class TestAnalyzeCommand : AnalyzeCommand
    {
        protected override AnalyzeContext CreateContext(
            AnalyzeOptions options,
            IAnalysisLogger logger,
            RuntimeConditions runtimeErrors,
            PropertiesDictionary policy = null,
            Uri targetUri = null)
        {
            AnalyzeContext context = base.CreateContext(options, logger, runtimeErrors, policy, targetUri);

            var aggregatingLogger = (AggregatingLogger)context.Logger;

            aggregatingLogger.Loggers.Add(new TestLogger());

            return context;
        }
    }
}
