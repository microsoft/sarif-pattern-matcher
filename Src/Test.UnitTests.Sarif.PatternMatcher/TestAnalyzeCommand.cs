// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class TestAnalyzeCommand : AnalyzeCommand
    {
        protected override AnalyzeContext CreateScanTargetContext(AnalyzeContext globalContext)
        {
            globalContext = base.CreateScanTargetContext(globalContext);

            var aggregatingLogger = (AggregatingLogger)globalContext.Logger;
            aggregatingLogger.Loggers.Add(new TestLogger());

            return globalContext;
        }
    }
}
