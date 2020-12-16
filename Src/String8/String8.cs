// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Text;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher.Strings
{
    /// <summary>
    ///  Represents a block of UTF8 text in a slice of a byte array.
    /// </summary>
    public struct String8 : IComparable<string>, IComparable<String8>, IEquatable<string>, IEquatable<String8>
    {
        public static String8 Empty = new String8(null, 0, 0);

        public String8(byte[] array, int index, int length)
        {
            Array = array;
            Index = index;
            Length = length;
        }

        public byte[] Array { get; }

        public int Index { get; }

        public int Length { get; }

        public bool IsEmpty => Length == 0;

        public static String8 ConvertExpensively(string value)
        {
            byte[] buffer = null;
            return String8.Convert(value, ref buffer);
        }

        /// <summary>
        ///  Convert a .NET string [UTF-16] to a UTF-8 String8, using an existing byte[].
        ///  This method will allocate or expand the byte[] if needed.
        ///  Declare the array outside a loop or method so that it can be used many times.
        /// </summary>
        /// <param name="value">.NET string to convert.</param>
        /// <param name="buffer">byte[] to convert into.</param>
        /// <param name="fromBufferIndex">Index in byte[] to start writing value to, if not the beginning.</param>
        /// <returns>String8 instance for the UTF-8 converted copy of 'value'.</returns>
        public static String8 Convert(string value, ref byte[] buffer, int fromBufferIndex = 0)
        {
            if (string.IsNullOrEmpty(value)) { return String8.Empty; }

            // Allocate or expand the buffer if needed
            int length = Encoding.UTF8.GetByteCount(value);
            if (buffer == null || fromBufferIndex + length > buffer.Length) { buffer = new byte[fromBufferIndex + length]; }

            // Convert the bytes at the beginning of the buffer
            int lengthWritten = Encoding.UTF8.GetBytes(value, 0, value.Length, buffer, fromBufferIndex);
            return new String8(buffer, fromBufferIndex, lengthWritten);
        }

        /// <summary>
        ///  Read a file directly into a UTF-8 String8, using an existing byte[].
        ///  This method will allocate or expand the byte[] if needed.
        ///  Declare the array outside a loop or method so that it can be used many times.
        /// </summary>
        /// <param name="filePath">File path that will be read to convert.</param>
        /// <param name="buffer">byte[] to convert into.</param>
        /// <param name="fromBufferIndex">Index in byte[] to start writing value to, if not the beginning.</param>
        /// <returns>String8 instance for the UTF-8 converted copy of 'value'.</returns>
        public static String8 ReadFile(string filePath, ref byte[] buffer, int fromBufferIndex = 0)
        {
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                int length = (int)stream.Length;
                if (buffer == null || fromBufferIndex + length > buffer.Length) { buffer = new byte[fromBufferIndex + length]; }

                int lengthWritten = stream.Read(buffer, fromBufferIndex, length);
                return new String8(buffer, fromBufferIndex, lengthWritten);
            }
        }

        /// <summary>
        ///  Translate a UTF-8 index (from an RE2 match) to a UTF-16 match (safe for indexing into a .NET string).
        ///  Takes an optional previous mapping, so it doesn't have to rescan from the beginning of the file each time.
        /// </summary>
        /// <remarks>
        /// <para>
        ///  UTF-8:
        ///    0xxxxxxx [lt 0x80] - First byte of single byte character
        ///    10xxxxxx [lt 0xC0] - Non-first byte of any multi-byte character
        ///    110xxxxx [lt 0xE0] - First byte of two byte character
        ///    1110xxxx [lt 0xF0] - First byte of three byte character
        ///    11110xxx [lt 0xF8] - First byte of four byte character.
        /// </para>
        /// <para>
        ///    All Unicode codepoints up to U+FFFF fit in one UTF-16 char.
        ///    UTF-8 can store 4 + 6 + 6 bits = 16 bits in a three byte encoding,
        ///    so all UTF-8 three byte and smaller characters will be one UTF-16 character.
        /// </para>
        /// </remarks>
        /// <param name="index">UTF-8 index to translate.</param>
        /// <param name="text8">String8 value.</param>
        /// <param name="previousUtf8Index">A previous UTF8 index translated, if available.</param>
        /// <param name="previousUtf16Index">The UTF-16 equivalent of the previous index, if available.</param>
        /// <returns>UTF-16 index corresponding to the UTF-8 index passed in.</returns>
        public static int Utf8ToUtf16(int index, String8 text8, int previousUtf8Index = 0, int previousUtf16Index = 0)
        {
            if (index < 0 || index > text8.Length) { throw new ArgumentOutOfRangeException(nameof(index)); }
            if (text8.Array == null) { throw new ArgumentNullException("text.Array"); }
            if (text8.Index < 0 || text8.Length < 0 || text8.Index + text8.Length > text8.Array.Length) { throw new ArgumentOutOfRangeException("text"); }

            // The first character is always the same
            if (index == 0) { return 0; }

            int startIndex = 0;
            int utf16Index = 0;

            // Track from the previous match, if it's available and before the current one
            if (previousUtf8Index > 0 && previousUtf8Index <= index)
            {
                startIndex = previousUtf8Index;
                utf16Index = previousUtf16Index;
            }

            // Count the number of UTF16 characters before text8[index]
            int currentLength = 0;
            for (int i = startIndex; i <= index - 1; ++i)
            {
                byte c = text8.Array[i + text8.Index];

                if (c >= 0x80 && c < 0xC0)
                {
                    // Continuation Byte; don't count (we figure out the counts from the first byte only)
                }
                else
                {
                    // Add the previous character length (now that it's done)
                    utf16Index += currentLength;

                    // This character will be one UTF-16 char if it's 1-3 bytes, and two if it's 4 bytes (0xF0+)
                    currentLength = c < 0xF0 ? 1 : 2;
                }
            }

            // If the character being pointed to isn't a continuation character, it's a new index
            byte last = index < text8.Length ? text8.Array[index + text8.Index] : (byte)0;
            if (!(last >= 0x80 && last < 0xC0)) { utf16Index += currentLength; }

            return utf16Index;
        }

        /// <summary>
        ///  Convert a String8 to the .NET string representation. Causes allocation and isn't cached.
        /// </summary>
        /// <returns>string instance.</returns>
        public override string ToString()
        {
            return Length == 0 ? string.Empty : Encoding.UTF8.GetString(Array, Index, Length);
        }

        /// <summary>
        ///  Get a String8 for the given substring of the overall string.
        /// </summary>
        /// <param name="index">0-based index from which to start substring.</param>
        /// <param name="length">Number of UTF8 bytes to include in substring.</param>
        /// <returns>String8 instance for substring.</returns>
        public String8 Substring(int index, int length)
        {
            // Verify in bounds
            if (index < 0) { throw new ArgumentOutOfRangeException(nameof(index)); }
            if (length < 0 || index + length > Length) { throw new ArgumentOutOfRangeException(nameof(length)); }

            // Build a substring tied to the same buffer
            return new String8(Array, Index + index, length);
        }

        /// <summary>
        ///  Compare this String8 to a .NET string. Will not allocate if the other string is ASCII only.
        /// </summary>
        /// <param name="other">string to compare to.</param>
        /// <returns>Negative if this String8 sorts earlier, zero if equal, positive if this String8 sorts later.</returns>
        public int CompareTo(string other)
        {
            int commonLength = Math.Min(this.Length, other.Length);
            for (int i = 0; i < commonLength; ++i)
            {
                byte tC = Array[Index + i];

                char oC = other[i];
                if ((ushort)oC < 0x80)
                {
                    int cmp = tC.CompareTo((byte)oC);
                    if (cmp != 0) { return cmp; }
                }
                else
                {
                    // Multi-byte strings - fall back
                    return string.CompareOrdinal(this.ToString(), other);
                }
            }

            return this.Length.CompareTo(other.Length);
        }

        /// <summary>
        ///  Compare this String8 to another one. Returns which String8 sorts earlier.
        /// </summary>
        /// <param name="other">String8 to compare to.</param>
        /// <returns>Negative if this String8 sorts earlier, zero if equal, positive if this String8 sorts later.</returns>
        public int CompareTo(String8 other)
        {
            // If String8s point to the same thing, return the same
            if (other.Index == Index && other.Array == Array && other.Length == Length) { return 0; }

            // If one or the other is empty, the non-empty one is greater
            if (this.IsEmpty)
            {
                return other.IsEmpty ? 0 : -1;
            }
            else if (other.IsEmpty)
            {
                return 1;
            }

            // Next, compare up to the length both strings are
            int cmp = CompareToCommonLength(other);
            if (cmp != 0) { return cmp; }

            // If all bytes are equal, the longer one is later
            return Length.CompareTo(other.Length);
        }

        public bool Equals(string other)
        {
            return CompareTo(other) == 0;
        }

        public bool Equals(String8 other)
        {
            return CompareTo(other) == 0;
        }

        private int CompareToCommonLength(String8 other)
        {
            int commonLength = Math.Min(this.Length, other.Length);
            for (int i = 0; i < commonLength; ++i)
            {
                int cmp = Array[Index + i].CompareTo(other.Array[other.Index + i]);
                if (cmp != 0) { return cmp; }
            }

            return 0;
        }
    }
}
