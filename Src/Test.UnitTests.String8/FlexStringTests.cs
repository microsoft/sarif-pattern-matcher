// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher.Strings
{
    public class FlexStringTests
    {
        [Fact]
        public void FlexString_Basics()
        {
            string sample;
            String8 sample8;
            FlexString sampleF, sampleF2;

            // Null handling
            Assert.True(FlexString.IsNullOrEmpty((FlexString)null));
            Assert.True(FlexString.IsNullOrEmpty((string)null));
            Assert.True(FlexString.IsNullOrEmpty(""));
            Assert.True(FlexString.IsNullOrEmpty(String8.Empty));

            Assert.True(FlexString.IsNull((FlexString)null));
            Assert.True(FlexString.IsNull((string)null));

            sample = null;
            sampleF = sample;
            sample8 = sampleF;
            Assert.True(FlexString.IsNullOrEmpty(sampleF));

            //Null check with null strings
            Assert.True(FlexString.IsNull(sample));
            Assert.True(FlexString.IsNull(sampleF));
            Assert.False(FlexString.IsNull(sample8));

            // Implicit conversions
            sample = "sample";
            sampleF = sample;
            sample8 = sampleF;
            Assert.Equal("sample", sample8.ToString());

            //Null check with populated strings
            Assert.False(FlexString.IsNull(sample));
            Assert.False(FlexString.IsNull(sampleF));
            Assert.False(FlexString.IsNull(sample8));

            sample8 = String8.ConvertExpensively("sample2");
            sampleF = sample8;
            sample = sampleF;
            Assert.Equal("sample2", sample);

            // CompareTo
            Assert.Equal(0, sampleF.CompareTo(sample));
            Assert.Equal(0, sampleF.CompareTo(sample8));
            Assert.Equal(0, sampleF.CompareTo(sampleF));
            sampleF = "sample3";
            Assert.NotEqual(0, sampleF.CompareTo(sample));
            Assert.NotEqual(0, sampleF.CompareTo(sample8));
            sampleF2 = "sample3";
            Assert.Equal(0, sampleF.CompareTo(sampleF2));
            sampleF2 = "different";
            Assert.NotEqual(0, sampleF.CompareTo(sampleF2));
        }
    }
}
