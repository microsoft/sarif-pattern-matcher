// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using FluentAssertions;

using Xunit;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace Microsoft.RE2.Managed
{
    public class FlexMatchValueComparerTests
    {
        [Fact]
        public void FlexMatchValueComparer_ComparerInSet()
        {
            var hashSet = new HashSet<FlexMatch>
            {
                new FlexMatch { Value = "1" },
                new FlexMatch { Value = "1" }
            };
            hashSet.Count.Should().Be(2);

            hashSet = new HashSet<FlexMatch>(FlexMatchValueComparer.Instance)
            {
                new FlexMatch { Value = "1" },
                new FlexMatch { Value = "1" }
            };
            hashSet.Count.Should().Be(1);
        }

        [Fact]
        public void FlexMatchValuComparer_Equality()
        {
            var flex1 = new FlexMatch { Value = "1" };
            var flex2 = new FlexMatch { Value = "1" };
            var flex3 = new FlexMatch { Value = "2" };

            FlexMatchValueComparer comparer = FlexMatchValueComparer.Instance;
            comparer.Equals(null, null).Should().BeTrue();
            comparer.Equals(flex1, flex1).Should().BeTrue();
            comparer.Equals(flex1, flex2).Should().BeTrue();
            comparer.Equals(flex1, null).Should().BeFalse();
            comparer.Equals(null, flex1).Should().BeFalse();
            comparer.Equals(flex1, flex3).Should().BeFalse();
        }

        [Fact]
        public void FlexMatchValuComparer_GetHashCode()
        {
            FlexMatch flex = null;
            FlexMatchValueComparer comparer = FlexMatchValueComparer.Instance;
            comparer.GetHashCode(flex).Should().Be(0);

            flex = new FlexMatch();
            comparer.GetHashCode(flex).Should().Be(0);

            flex = new FlexMatch { Value = "1" };
            comparer.GetHashCode(flex).Should().Be("1".GetHashCode());
        }
    }
}
