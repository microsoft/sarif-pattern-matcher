// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using FluentAssertions;

using Microsoft.Strings.Interop;

using Xunit;

namespace Microsoft.RE2.Managed
{
    public class FlexMatchTests
    {
        [Fact]
        public void FlexMatch_ShouldNotThrow()
        {
            var flexMatch = new FlexMatch();
            flexMatch.ToString().Should().Be(string.Empty);

            flexMatch.Value = new FlexString(null);
            flexMatch.ToString().Should().Be(string.Empty);

            flexMatch.Value = new FlexString("flexMatch");
            flexMatch.ToString().Should().Be("flexMatch");

            byte[] buffer = null;
            var value = String8.Convert("flexMatch", ref buffer);
            flexMatch.Value = new FlexString(value);
            flexMatch.ToString().Should().Be("flexMatch");
        }
    }
}
