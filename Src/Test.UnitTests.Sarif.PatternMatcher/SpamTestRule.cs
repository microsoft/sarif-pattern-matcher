﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Composition;
using System.Linq;
using System.Reflection;
using System.Resources;
using System.Threading;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.Driver;
using Microsoft.CodeAnalysis.Sarif.Driver.Sdk;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher;

namespace Microsoft.CodeAnalysis.Sarif
{
    // Test rule for provoking various behaviors designed to increase code coverage. This rule can be configured
    // via explicitly passed configuration, by injecting test behaviors into a thread static variable, or
    // implicitly via the name of the scan targets.
    [Export(typeof(ReportingDescriptor)), Export(typeof(IOptionsProvider)), Export(typeof(Skimmer<TestAnalysisContext>))]
    internal class SpamTestRule : Skimmer<AnalyzeContext>, IOptionsProvider
    {
        internal static int s_seed = (int)DateTime.UtcNow.Ticks;
        internal static Random s_random = new Random(s_seed);

        [ThreadStatic]
        internal static TestRuleBehaviors s_testRuleBehaviors;

        public SpamTestRule()
        {
            if (s_testRuleBehaviors.HasFlag(TestRuleBehaviors.RaiseExceptionInvokingConstructor))
            {
                throw new InvalidOperationException(nameof(TestRuleBehaviors.RaiseExceptionInvokingConstructor));
            }
        }

        private const string TestRuleId = "TEST1001";

        protected override ResourceManager ResourceManager => SkimmerBaseTestResources.ResourceManager;

        protected override IEnumerable<string> MessageResourceNames => new List<string>
        {
            nameof(SkimmerBaseTestResources.TEST1001_Failed),
            nameof(SkimmerBaseTestResources.TEST1001_Pass),
            nameof(SkimmerBaseTestResources.TEST1001_Note),
            nameof(SkimmerBaseTestResources.TEST1001_Open),
            nameof(SkimmerBaseTestResources.TEST1001_Review),
            nameof(SkimmerBaseTestResources.TEST1001_Information),
            nameof(SkimmerBaseTestResources.NotApplicable_InvalidMetadata)
        };

        public override SupportedPlatform SupportedPlatforms
        {
            get
            {
                if (s_testRuleBehaviors.HasFlag(TestRuleBehaviors.TreatPlatformAsInvalid))
                {
                    return SupportedPlatform.Unknown;
                }

                return SupportedPlatform.All;
            }
        }

        private string _id;
        public override string Id
        {
            get
            {
                if (s_testRuleBehaviors == TestRuleBehaviors.RaiseExceptionAccessingId)
                {
                    throw new InvalidOperationException(nameof(TestRuleBehaviors.RaiseExceptionAccessingId));
                }

                return _id ?? TestRuleId;
            }
            set
            {
                _id = value;
            }
        }

        private string _name;
        public override string Name
        {
            get
            {
                if (s_testRuleBehaviors == TestRuleBehaviors.RaiseExceptionAccessingName)
                {
                    throw new InvalidOperationException(nameof(TestRuleBehaviors.RaiseExceptionAccessingId));
                }

                return _name ?? base.Name;
            }
            set
            {
                _name = value;
            }
        }

        public override void Initialize(AnalyzeContext context)
        {
            if (context.Policy.GetProperty(TestRule.Behaviors).HasFlag(TestRuleBehaviors.RaiseExceptionInvokingInitialize))
            {
                throw new InvalidOperationException(nameof(TestRuleBehaviors.RaiseExceptionInvokingInitialize));
            }
        }

        public override AnalysisApplicability CanAnalyze(AnalyzeContext context, out string reasonIfNotApplicable)
        {
            AnalysisApplicability applicability = AnalysisApplicability.ApplicableToSpecifiedTarget;
            reasonIfNotApplicable = null;

            if (context.Policy.GetProperty(TestRule.Behaviors).HasFlag(TestRuleBehaviors.RaiseExceptionInvokingCanAnalyze))
            {
                throw new InvalidOperationException(nameof(TestRuleBehaviors.RaiseExceptionInvokingCanAnalyze));
            }

            if (context.Policy.GetProperty(TestRule.Behaviors).HasFlag(TestRuleBehaviors.RegardAnalysisTargetAsNotApplicable))
            {
                reasonIfNotApplicable = "testing NotApplicableToSpecifiedTarget";
                return AnalysisApplicability.NotApplicableToSpecifiedTarget;
            }

            string fileName = context.CurrentTarget.Uri.ToString();

            if (fileName.Contains("NotApplicable"))
            {
                reasonIfNotApplicable = "test was configured to find target not applicable";
                applicability = AnalysisApplicability.NotApplicableToSpecifiedTarget;
            }

            return applicability;
        }

        public override MultiformatMessageString FullDescription { get { return new MultiformatMessageString { Text = "This is the full description for TST1001" }; } }

        public override void Analyze(AnalyzeContext context)
        {
            int delay = context.Policy.GetProperty(TestRule.DelayInMilliseconds);
            Thread.Sleep(delay);

            TestRuleBehaviors testRuleBehaviors = context.Policy.GetProperty(TestRule.Behaviors);

            switch (testRuleBehaviors)
            {
                case TestRuleBehaviors.RaiseExceptionInvokingAnalyze:
                {
                    MethodInfo mi = this.GetType().GetMethod("RaiseExceptionViaReflection");
                    mi.Invoke(null, new object[] { });
                    break;
                }

                case TestRuleBehaviors.RaiseTargetParseError:
                {
                    Errors.LogTargetParseError(
                        context,
                        new Region
                        {
                            StartLine = 42,
                            StartColumn = 54
                        },
                        "Could not parse target.");
                    break;
                }

                case TestRuleBehaviors.LogError:
                {
                    uint errorsCount = context.Policy.GetProperty(TestRule.ErrorsCount);

                    for (uint i = 0; i < errorsCount; i++)
                    {
                        context.Logger.Log(this,
                            RuleUtilities.BuildResult(FailureLevel.Error, context, null,
                            nameof(SkimmerBaseTestResources.TEST1001_ErrorMessageFromTestBehavior),
                            context.CurrentTarget.Uri.GetFileName()));

                        Thread.Sleep(s_random.Next(0, 10));
                    }

                    break;
                }

                default:
                {
                    break;
                }
            }

            int fooInstanceCount = CountAllInstancesOfFoo(context.CurrentTarget.Contents);

            for (uint i = 0; i < fooInstanceCount; i++)
            {
                context.Logger.Log(this,
                    RuleUtilities.BuildResult(FailureLevel.Error, context, null,
                    nameof(SkimmerBaseTestResources.TEST1001_FoundAFooInTheFile),
                    context.CurrentTarget.Uri.GetFileName()));
            }

            string fileName = context.CurrentTarget.Uri.ToString();

            if (fileName.Contains(nameof(FailureLevel.Error), StringComparison.OrdinalIgnoreCase))
            {
                context.Logger.Log(this,
                    RuleUtilities.BuildResult(FailureLevel.Error, context, null,
                    nameof(SkimmerBaseTestResources.TEST1001_Failed),
                    context.CurrentTarget.Uri.GetFileName()));
            }

            if (fileName.Contains(nameof(FailureLevel.Warning), StringComparison.OrdinalIgnoreCase))
            {
                context.Logger.Log(this,
                    RuleUtilities.BuildResult(FailureLevel.Warning, context, null,
                    nameof(SkimmerBaseTestResources.TEST1001_Failed),
                    context.CurrentTarget.Uri.GetFileName()));
            }

            if (fileName.Contains(nameof(FailureLevel.Note), StringComparison.OrdinalIgnoreCase))
            {
                context.Logger.Log(this,
                    RuleUtilities.BuildResult(FailureLevel.Note, context, null,
                    nameof(SkimmerBaseTestResources.TEST1001_Note),
                    context.CurrentTarget.Uri.GetFileName()));
            }
            else if (fileName.Contains(nameof(ResultKind.Pass), StringComparison.OrdinalIgnoreCase))
            {
                context.Logger.Log(this,
                    RuleUtilities.BuildResult(ResultKind.Pass, context, null,
                    nameof(SkimmerBaseTestResources.TEST1001_Pass),
                    context.CurrentTarget.Uri.GetFileName()));
            }
            else if (fileName.Contains(nameof(ResultKind.Review), StringComparison.OrdinalIgnoreCase))
            {
                context.Logger.Log(this,
                    RuleUtilities.BuildResult(ResultKind.Review, context, null,
                    nameof(SkimmerBaseTestResources.TEST1001_Review),
                    context.CurrentTarget.Uri.GetFileName()));
            }
            else if (fileName.Contains(nameof(ResultKind.Open), StringComparison.OrdinalIgnoreCase))
            {
                context.Logger.Log(this,
                    RuleUtilities.BuildResult(ResultKind.Open, context, null,
                    nameof(SkimmerBaseTestResources.TEST1001_Open),
                    context.CurrentTarget.Uri.GetFileName()));
            }
            else if (fileName.Contains(nameof(ResultKind.Informational), StringComparison.OrdinalIgnoreCase))
            {
                context.Logger.Log(this,
                    RuleUtilities.BuildResult(ResultKind.Informational, context, null,
                    nameof(SkimmerBaseTestResources.TEST1001_Information),
                    context.CurrentTarget.Uri.GetFileName()));
            }
        }

        private int CountAllInstancesOfFoo(string fileContents)
        {
            if (string.IsNullOrEmpty(fileContents) || fileContents.IndexOf("foo") == -1)
            {
                return 0;
            }

            string[] tokens = fileContents.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return tokens.Where(t => t == "foo").Count();
        }

        public static void RaiseExceptionViaReflection()
        {
            throw new InvalidOperationException(nameof(TestRuleBehaviors.RaiseExceptionInvokingAnalyze));
        }

        public IEnumerable<IOption> GetOptions()
        {
            return new IOption[] { TestRule.Behaviors, TestRule.UnusedOption, TestRule.ErrorsCount };
        }

        private const string AnalyzerName = TestRuleId + "." + nameof(SpamTestRule);
    }
}
