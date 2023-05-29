// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public sealed class SpamEventNames
    {
        public const string ScanArtifact = nameof(RunRule);


        public const string Sniffing = nameof(Sniffing);
        public const string PostSniff = nameof(PostSniff);

        public const string RunRule = nameof(RunRule);

        public const string Phase0Regex = "Phase0-Regex";
        public const string Phase1StaticValidation = "Phase1-StaticValidation";
        public const string Phase2DynamicValidation = "Phase2-DynamicValidation";

        public const string RunRulePhase0Regex = $"{RunRule}/{Phase0Regex}";
        public const string RunRulePhase0RegexStop = $"{RunRulePhase0Regex}/Stop";
        public const string RunRulePhase0RegexStart = $"{RunRulePhase0Regex}/Start";

        public const string RunRulePhase1StaticValidation = $"{RunRule}/{Phase1StaticValidation}";
        public const string RunRulePhase1StaticValidationStop = $"{RunRulePhase1StaticValidation}/Stop";
        public const string RunRulePhase1StaticValidationStart = $"{RunRulePhase1StaticValidation}/Start";

        public const string RunRulePhase2DynamicValidation = $"{RunRule}/{Phase2DynamicValidation}";
        public const string RunRulePhase2DynamicValidationStop = $"{RunRulePhase2DynamicValidation}/Stop";
        public const string RunRulePhase2DynamicValidationStart = $"{RunRulePhase2DynamicValidation}/Start";

        // Reasons for various filtering conditions.
        public const string ContentsSniffNoMatch = nameof(ContentsSniffNoMatch);
    }
}
