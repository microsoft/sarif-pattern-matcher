// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public static class SpmiEvents
    {
        public static string ScanTargetSniff = nameof(ScanTargetSniff);
        public static string TargetFilteredBySniff = nameof(TargetFilteredBySniff);
        public static string TargetNotFilteredBySniff = nameof(TargetNotFilteredBySniff);
    }
}
