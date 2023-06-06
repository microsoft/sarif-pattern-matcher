// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;

using FluentAssertions;

using Microsoft.RE2.Managed;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class ValidatorsCacheTests
    {
        [Fact]
        public void ValidatorsCache_GetCombinations()
        {
            var input = new Dictionary<string, ISet<FlexMatch>>();
            IList<IDictionary<string, FlexMatch>> results = ValidatorsCache.GetCombinations(input);

            results.Should().BeEmpty();

            input["a"] = new HashSet<FlexMatch>(new[]
                { new FlexMatch() { Value = "a1" },
                  new FlexMatch() { Value = "a2" },
                });

            results = ValidatorsCache.GetCombinations(input);
            results.Count.Should().Be(CombinationsCount(input));

            input["b"] = new HashSet<FlexMatch>(new[]
                { new FlexMatch() { Value = "b1" },
                  new FlexMatch() { Value = "b2" },
                  new FlexMatch() { Value = "b3" }
                });

            results = ValidatorsCache.GetCombinations(input);
            results.Count.Should().Be(CombinationsCount(input));

            input["c"] = new HashSet<FlexMatch>(new[]
                { new FlexMatch() { Value = "c1" },
                  new FlexMatch() { Value = "c2" },
                  new FlexMatch() { Value = "c3" },
                  new FlexMatch() { Value = "c4" }
                });

            results = ValidatorsCache.GetCombinations(input);
            results.Count.Should().Be(CombinationsCount(input));

            var elements = new List<string>();
            for (int i = 0; i < results.Count; i++)
            {
                foreach (string key in results[i].Keys)
                {
                    elements.Add(results[i][key].Value);
                }
            }

            elements.Count.Should().Be(3 * CombinationsCount(input));

            int aCount = input["a"].Count;
            int bCount = input["b"].Count;
            int cCount = input["c"].Count;

            foreach (FlexMatch flexMatch in input["a"])
            {
                (elements.Where(e => e == flexMatch.Value).Count() == bCount * cCount).Should().BeTrue();
            }

            foreach (FlexMatch flexMatch in input["b"])
            {
                (elements.Where(e => e == flexMatch.Value).Count() == aCount * cCount).Should().BeTrue();
            }

            foreach (FlexMatch flexMatch in input["c"])
            {
                (elements.Where(e => e == flexMatch.Value).Count() == aCount * bCount).Should().BeTrue();
            }
        }

        private static int CombinationsCount(Dictionary<string, ISet<FlexMatch>> input)
        {
            int count = 1;

            foreach (string key in input.Keys)
            {
                count *= input[key].Count;
            }

            return count;
        }
    }
}
