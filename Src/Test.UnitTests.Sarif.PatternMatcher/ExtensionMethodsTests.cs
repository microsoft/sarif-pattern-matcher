// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using FluentAssertions;

using Microsoft.RE2.Managed;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class ExtensionMethodsTests
    {
        [Fact]
        public void ExtensionMethods_CopyToStringShouldBeValid()
        {
            var dict = new Dictionary<string, FlexMatch>();
            var flexMatch = new FlexMatch { Value = "test" };

            // ToString from empty, should be empty;
            Dictionary<string, string> copy = dict.ToStringDictionary();
            copy.Should().BeEmpty();

            // ToString should copy all values.
            dict.Add("key1", flexMatch);
            copy = dict.ToStringDictionary();
            copy.Should().NotBeEmpty();
            copy["key1"].Should().Be(flexMatch.Value);

            // Updating original, should not change copy.
            flexMatch.Value = "new-test";
            copy["key1"].Should().NotBe(flexMatch.Value);
        }

        [Fact]
        public void ExtensionMethods_CopyShouldGenerateNewReference()
        {
            var dict = new Dictionary<string, FlexMatch>();
            var flexMatch = new FlexMatch { Index = 1, Length = 1, Success = true, Value = "1" };

            // Copying empty, should be empty.
            Dictionary<string, FlexMatch> copy = dict.Copy();
            copy.Should().BeEmpty();

            // Adding to original dict, should keep copy intact.
            dict.Add("key1", flexMatch);
            copy.Should().BeEmpty();

            // Copying should bring all elements.
            copy = dict.Copy();
            copy.Should().NotBeEmpty();
            copy["key1"].Should().Be(flexMatch);
        }
    }
}
