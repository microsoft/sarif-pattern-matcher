// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public sealed class SpamEventNames
    {
        public const string ScanArtifact = nameof(RunRule);

        public const string Sniffing = nameof(Sniffing);
        public const string PostSniff = nameof(PostSniff);

        public const string RunRule = nameof(RunRule);

        public const string Phase0Sniff = "Phase0-Sniff";
        public const string Phase1Regex = "Phase1-Regex";
        public const string Phase2StaticValidation = "Phase2-StaticValidation";
        public const string Phase3DynamicValidation = "Phase3-DynamicValidation";

        public const string RunRulePhase0Sniff = $"{RunRule}/{Phase0Sniff}";
        public const string RunRulePhase1Regex = $"{RunRule}/{Phase1Regex}";
        public const string RunRulePhase2StaticValidation = $"{RunRule}/{Phase2StaticValidation}";
        public const string RunRulePhase3DynamicValidation = $"{RunRule}/{Phase3DynamicValidation}";

        // Reasons for various filtering conditions.
        public const string ContentsSniffNoMatch = nameof(ContentsSniffNoMatch);
    }
}
