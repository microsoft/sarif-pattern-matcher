// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class ValidatingVisitor : SarifRewritingVisitor
    {
        private readonly bool _retry;
        private readonly bool _enhancedReporting;
        private readonly ValidatorsCache _validators;
        private Run _run;

        public ValidatingVisitor(ValidatorsCache validators, bool enhancedReporting = false, bool retry = false)
        {
            _retry = retry;
            _validators = validators;
            _enhancedReporting = enhancedReporting;
        }

        public override Run VisitRun(Run node)
        {
            _run = node;
            return base.VisitRun(node);
        }

        public override Result VisitResult(Result node)
        {
            if (node.Fingerprints == null)
            {
                return node;
            }

            var fingerprint = new Fingerprint(node.Fingerprints);

            ReportingDescriptor rule = node.GetRule(_run);

            StaticValidatorBase staticValidator =
                ValidatorsCache.GetValidationMethods(rule.Id, _validators.RuleIdToValidationMethods);

            if (staticValidator is DynamicValidatorBase dynamicValidator)
            {
                // Our validation messages currently look like so.
                // {0:scanTarget}' contains {1:validationPrefix}{2:encoding}{3:secretKind}{4:validationSuffix}{5:validatorMessage}
                string message = null;
                IDictionary<string, string> options = new Dictionary<string, string>
                {
                    { "retry", _retry ? bool.TrueString : bool.FalseString },
                    { "enhancedReporting", _enhancedReporting ? bool.TrueString : bool.FalseString },
                };

                ResultKind kind = node.Kind;
                FailureLevel level = default;
                ResultLevelKind resultLevelKind = default;
                ValidationState state =
                    dynamicValidator.IsValidDynamic(ref fingerprint,
                                                          ref message,
                                                          options,
                                                          ref resultLevelKind);

                string validationPrefix = node.Message.Arguments[1];
                string validationSuffix = node.Message.Arguments[4];

                SearchSkimmer.SetPropertiesBasedOnValidationState(state,
                                                                  context: null,
                                                                  resultLevelKind,
                                                                  ref level,
                                                                  ref kind,
                                                                  ref validationPrefix,
                                                                  ref validationSuffix,
                                                                  ref message,
                                                                  pluginSupportsDynamicValidation: true);

                node.Level = level;
                node.Kind = kind;
                node.Message.Arguments[1] = validationPrefix;
                node.Message.Arguments[4] = validationSuffix;
                node.Message.Arguments[5] = SearchSkimmer.NormalizeValidatorMessage(message);
                node.Fingerprints[SearchSkimmer.AssetFingerprintCurrent] = fingerprint.GetAssetFingerprint();
            }

            return node;
        }
    }
}
