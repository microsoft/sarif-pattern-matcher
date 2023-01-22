// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Composition;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher;

namespace Microsoft.CodeAnalysis.Sarif
{
    // Test rule for provoking various behaviors designed to increase code coverage. This rule can be configured
    // via explicitly passed configuration, by injecting test behaviors into a thread static variable, or
    // implicitly via the name of the scan targets.
    [Export(typeof(ReportingDescriptor)), Export(typeof(IOptionsProvider)), Export(typeof(Skimmer<TestAnalysisContext>))]
    internal class BadlyBehavedRule : SpamTestRule
    {
        public override string Id => "5665000b-b7ad-48fb-8a70-47468d8d8338";

        public override void Analyze(AnalyzeContext context)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<IOption> GetOptions()
        {
            throw new NotImplementedException();
        }
    }
}
