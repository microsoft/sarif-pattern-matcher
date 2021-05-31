// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class ValidatorBaseTests : ValidatorBase
    {
        [Fact]
        public void ValidatorBase_ParseValue()
        {
            ValidatorBase.ParseValue(null).Should().BeNull();
            ValidatorBase.ParseValue(string.Empty).Should().BeNullOrWhiteSpace();

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

        [Fact]
        public void ScanIdentityGuid_MustBeGuid()
        {
            Assert.Throws<ArgumentException>(() => ScanIdentityGuid = "notGuid");

            string firstGuidValue = ScanIdentityGuid;
            ScanIdentityGuid.Should().NotBeNullOrEmpty();
            ScanIdentityGuid.Should().Be(firstGuidValue);

            var guid = Guid.NewGuid();
            ScanIdentityGuid = $"{guid}";
            ScanIdentityGuid.Should().Be($"{guid}");
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(Dictionary<string, FlexMatch> groups)
        {
            throw new System.NotImplementedException();
        }
    }
}
