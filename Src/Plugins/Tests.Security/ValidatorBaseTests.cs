// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using FluentAssertions;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class ValidatorBaseTests
    {
        [Fact]
        public void ValidatorBase_ParseValue()
        {
            ValidatorBase.ParseValue(null).Should().BeNull();
            ValidatorBase.ParseValue(string.Empty).Should().Be(string.Empty);

            var strings = new List<string>
            {
                "some-value",
                "some-key=some-value",
                " some-value ",
                "some-value ",
                " some-value",
                "\tsome-value",
                "some-value\t"
            };

            foreach (string text in strings)
            {
                ValidatorBase.ParseValue(text).Should().Be("some-value");
            }
        }
    }
}
