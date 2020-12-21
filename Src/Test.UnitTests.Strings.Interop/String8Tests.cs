// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;

namespace Strings.Interop
{
    public class String8Tests
    {
        [Fact]
        public void Utf8ToUtf16()
        {
            byte[] buffer = null;
            String8 value = String8.Convert("abc    def", ref buffer);
            String8 replacement;

            // Bounds
            Assert.Equal(0, String8.Utf8ToUtf16(0, value));
            Assert.Equal(value.Length, String8.Utf8ToUtf16(value.Length, value));

            // All single byte: Verify all indices are the same
            for (int i = 0; i < value.Length; ++i)
            {
                Assert.Equal(i, String8.Utf8ToUtf16(i, value));
                if (i > 0) { Assert.Equal(i, String8.Utf8ToUtf16(i, value, i - 1, i - 1)); }
            }

            // Place a two-byte character right after 'abc' [¼]
            replacement = String8.Convert("\u00BC", ref buffer, 3);
            Assert.Equal(2, replacement.Length);

            // 0123345678  [Index 3-4 are char 3]
            // abc..  def
            Assert.Equal(2, String8.Utf8ToUtf16(2, value));
            Assert.Equal(3, String8.Utf8ToUtf16(3, value));
            Assert.Equal(3, String8.Utf8ToUtf16(4, value));
            Assert.Equal(4, String8.Utf8ToUtf16(5, value));
            Assert.Equal(5, String8.Utf8ToUtf16(6, value));

            // Place a three byte character right after 'Two' [ᚠ]
            replacement = String8.Convert("\u16A0", ref buffer, 3);
            Assert.Equal(3, replacement.Length);

            // 0123334567 [Index 3-5 are char 3]
            // abc... def
            Assert.Equal(2, String8.Utf8ToUtf16(2, value));
            Assert.Equal(3, String8.Utf8ToUtf16(3, value));
            Assert.Equal(3, String8.Utf8ToUtf16(4, value));
            Assert.Equal(3, String8.Utf8ToUtf16(5, value));
            Assert.Equal(4, String8.Utf8ToUtf16(6, value));
            Assert.Equal(5, String8.Utf8ToUtf16(7, value));

            // Place a four byte character right after 'Two' [𐤈]
            replacement = String8.Convert("\U00010908", ref buffer, 3);
            Assert.Equal(4, replacement.Length);

            // 0123333567 [Index 3-6 are char 3 AND it's length 2, so next is index 5]
            // abc....def
            Assert.Equal(2, String8.Utf8ToUtf16(2, value));
            Assert.Equal(3, String8.Utf8ToUtf16(3, value));
            Assert.Equal(3, String8.Utf8ToUtf16(4, value));
            Assert.Equal(3, String8.Utf8ToUtf16(5, value));
            Assert.Equal(3, String8.Utf8ToUtf16(6, value));
            Assert.Equal(5, String8.Utf8ToUtf16(7, value));
            Assert.Equal(6, String8.Utf8ToUtf16(8, value));
        }

        [Fact]
        public void Utf8ToUtf16_All()
        {
            // Validate that index conversions on "a*b" map correctly for every Unicode codepoint
            byte[] buffer = new byte[10];
            String8.Convert("a", ref buffer);

            for (int codepoint = 0; codepoint < 0x10FFFF; ++codepoint)
            {
                // Skip illegal codepoints
                if (codepoint >= 0xD800 && codepoint <= 0xDFFF) { continue; }

                // Convert the codepoint to UTF16
                string value = char.ConvertFromUtf32(codepoint);

                // Append it to the String8 after 'a'
                String8 value8 = String8.Convert(value, ref buffer, 1);

                // Append 'b' after that
                String8.Convert("b", ref buffer, value8.Index + value8.Length);

                // Map the whole value
                String8 whole8 = new String8(buffer, 0, value8.Index + value8.Length + 1);

                // 'a' should always map to index 0
                Assert.Equal(0, String8.Utf8ToUtf16(0, whole8));

                // 'b' should always map to the last .NET char (the length needed for the .NET string + 1 for 'a')
                Assert.Equal(1 + value.Length, String8.Utf8ToUtf16(whole8.Length - 1, whole8));

                // All indices in between are the middle character (index 1, since it's after 'a')
                for (int i = 1; i < whole8.Length - 1; ++i)
                {
                    Assert.Equal(1, String8.Utf8ToUtf16(i, whole8));
                }
            }
        }
    }
}
