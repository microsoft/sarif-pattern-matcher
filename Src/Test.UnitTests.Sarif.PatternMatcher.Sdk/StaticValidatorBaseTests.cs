// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Newtonsoft.Json;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class StaticValidatorBaseTests
    {
        [Fact]
        public void StaticValidatorBase_IsValidStaticIsThreadSafe()
        {
            var testStaticValidator = new TestStaticValidator();

            int id = 0;

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Environment.ProcessorCount * 2,
            };

            var perFileFingerprintHash = new HashSet<string>();

            Parallel.For(0, 1, (_) =>
            {
                Interlocked.Increment(ref id);

                for (int iterations = 0; iterations < 100; iterations++)
                {
                    var groups = new Dictionary<string, FlexMatch>
                    {
                        { "scanTargetFullPath", new FlexMatch { Value = Guid.NewGuid().ToString()} },
                        { "0", new FlexMatch { Value = Guid.NewGuid().ToString() } }
                    };

                    for (int i = 0; i < 1; i++)
                    {
                        groups[i.ToString()] =
                            new FlexMatch
                            {
                                Value = Guid.NewGuid().ToString()
                            };
                    }
                    testStaticValidator.IsValidStatic(groups, perFileFingerprintHash);
                }
            });
        }

        private class TestStaticValidator : StaticValidatorBase
        {
            protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
            {
                // Our job in this test is to produce multiple findings in the same file.
                // This will provoke StaticValidatorBase's per file caching mechanism, so
                // that we can ensure it is thread-safe.

                // Arbitrarily 10 results per file should do it. What's being simulated here
                // is that a file either contains duplicates of the same secret, or we have
                // a poorly authored regex that produces lots of duplicative matches that
                // resolve to the same secret (or a single secret plus related noise). The
                // static validator base tries to help with this by eliminating all but the 
                // first find in a file, for every unique secret, by fingerprint.
                //
                var results = new List<ValidationResult>();
                for (int i = 0; i < 10; i++)
                {
                    results.Add(new ValidationResult
                    {
                        Fingerprint = new Fingerprint() { Secret = "DuplicatedSecretValue" }
                    });
                }

                // As follow-on work, we will dip into the groups dictionary, in case doing
                // that also flushes any problems. This also has the useful outcome of 
                // introducing some execution cycles in this helper, which is often 
                // helpful when trying to provoke / validating threading behaviors.

                // These groups are always available;
                string scanTargetFullPath = groups["scanTargetFullPath"].Value;
                string fullMatch = groups["0"].Value;

                int groupAccesses = 100;
                for (int i = 0; i < groupAccesses; i++)
                {
                    // Retrieve a value...
                    groups.TryGetValue(i.ToString(), out FlexMatch value);

                    // We don't do anything special to make the incoming groups
                    // dictionary immutable, so an extension can change it.
                    // 
                    // We'll generate a unique key by simply doubling the count of accesses.
                    groups[(i + groupAccesses).ToString()] =
                        new FlexMatch() { Value = Guid.NewGuid().ToString() };
                }

                return results;
            }
        }
    }
}
