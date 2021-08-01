// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Text;

using FluentAssertions;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public class Crc32Tests
    {
        [Fact]
        public void Crc32_GeneratesValidChecksumForSimpleTestValue()
        {
            uint wellKnownChecksumForTestValue = 0xd87f7e0c;

            byte[] input = Encoding.ASCII.GetBytes("test");

            Calculate(input, wellKnownChecksumForTestValue);
        }

        [Fact]
        public void Crc32_GeneratesValidChecksumForLongerTestValue()
        {
            uint wellKnownChecksumForTestValue = 0x89b46555;

            byte[] input = Encoding.ASCII.GetBytes(new string('a', 64));

            Calculate(input, wellKnownChecksumForTestValue);
        }

        [Fact]
        public void Crc32_ChecksumGeneratesExpectedConstantWhenProcessed()
        {
            // CRC32 algorithms have the interesting property of producing
            // a constant value when the CRC for an input buffer
            // is appended to the data and the checksum is recomputed
            // (for the original data and the appended checksum).
            //
            // This contanst is 0x2144DF1C for CRC-32.
            uint crc32Constant = 0x2144DF1C;

            byte[] input = new byte[8];

            input[0] = (byte)'t';
            input[1] = (byte)'e';
            input[2] = (byte)'s';
            input[3] = (byte)'t';

            // The checksum for 'test' is 0xd87f7e0c, persisted
            // to the buffer in little-endian order.
            input[7] = 0xd8;
            input[6] = 0x7f;
            input[5] = 0x7e;
            input[4] = 0x0c;

            Calculate(input, crc32Constant);
        }

        private static void Calculate(byte[] input, uint expectedChecksum)
        {
            uint actual = Crc32.Calculate(input);
            actual.Should().Be(expectedChecksum);

            actual = Crc32.Calculate(0, input, 0, input.Length);
            actual.Should().Be(expectedChecksum);
        }
    }
}
