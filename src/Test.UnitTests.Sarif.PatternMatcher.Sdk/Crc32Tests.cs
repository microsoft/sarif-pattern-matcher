// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
            byte[] input = Encoding.ASCII.GetBytes("test");

            uint wellKnownIEEEChecksumForTestValue = 0xd87f7e0c;
            Calculate(input, wellKnownIEEEChecksumForTestValue);

            uint wellKnownCastagnoliChecksumForTestValue = 0x86A072C0;
            Calculate(input, wellKnownCastagnoliChecksumForTestValue, Crc32.Crc32CastagnoliTable);
        }

        [Fact]
        public void Crc32_GeneratesValidChecksumForLongerTestValue()
        {
            byte[] input = Encoding.ASCII.GetBytes(new string('a', 64));

            uint wellKnownIEEEChecksumForTestValue = 0x89b46555;
            Calculate(input, wellKnownIEEEChecksumForTestValue);

            uint wellKnownCastagnoliChecksumForTestValue = 0x37AEEE33;
            Calculate(input, wellKnownCastagnoliChecksumForTestValue, Crc32.Crc32CastagnoliTable);
        }

        // CRC32 algorithms have the interesting property of producing
        // a constant value when the CRC for an input buffer
        // is appended to the data and the checksum is recomputed
        // (for the original data and the appended checksum).
        // The constant is different for different Polynomial
        [Fact]
        public void Crc32IEEE_ChecksumGeneratesExpectedConstantWhenProcessed()
        {
            // The contanst is 0x2144DF1C for CRC-32 using IEEE Polynomial
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

            byte[] inputLong = new byte[68];
            for (int i = 0; i < 64; i++)
            {
                inputLong[i] = (byte)'a';
            }

            // The checksum for 64 bytes of 'a' is 0x89b46555, persisted
            // to the buffer in little-endian order.
            inputLong[67] = 0x89;
            inputLong[66] = 0xb4;
            inputLong[65] = 0x65;
            inputLong[64] = 0x55;

            Calculate(inputLong, crc32Constant);
        }

        [Fact]
        public void Crc32Castagnoli_ChecksumGeneratesExpectedConstantWhenProcessed()
        {
            // The contanst is 0x48674BC7 for CRC-32 using Castagnoli Polynomial
            uint crc32Constant = 0x48674BC7;

            byte[] input = new byte[8];

            input[0] = (byte)'t';
            input[1] = (byte)'e';
            input[2] = (byte)'s';
            input[3] = (byte)'t';

            // The checksum for 'test' is 0x86A072C0, persisted
            // to the buffer in little-endian order.
            input[7] = 0x86;
            input[6] = 0xA0;
            input[5] = 0x72;
            input[4] = 0xC0;

            Calculate(input, crc32Constant, Crc32.Crc32CastagnoliTable);

            byte[] inputLong = new byte[68];
            for (int i = 0; i < 64; i++)
            {
                inputLong[i] = (byte)'a';
            }

            // The checksum for 64 bytes of 'a' is 0x37AEEE33, persisted
            // to the buffer in little-endian order.
            inputLong[67] = 0x37;
            inputLong[66] = 0xAE;
            inputLong[65] = 0xEE;
            inputLong[64] = 0x33;

            Calculate(inputLong, crc32Constant, Crc32.Crc32CastagnoliTable);
        }

        private static void Calculate(byte[] input, uint expectedChecksum, uint[] crc32Table = null)
        {
            uint actual = Crc32.Calculate(input, crc32Table);
            actual.Should().Be(expectedChecksum);

            actual = Crc32.Calculate(0, input, 0, input.Length, crc32Table);
            actual.Should().Be(expectedChecksum);
        }
    }
}
