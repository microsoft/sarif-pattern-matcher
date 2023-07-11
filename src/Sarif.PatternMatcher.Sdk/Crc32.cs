// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public static class Crc32
    {
        // https://crc32.online/
        // https://github.com/force-net/Crc32.NET
        // https://en.wikipedia.org/wiki/Cyclic_redundancy_check
        // This is the 'reversed representation' polynomial for
        // little-endian implementations, i.e., the bitwise
        // reflection of 0x04C11DB7;
        // CRC-32-IEEE 802.3 polynomial
        private const uint Crc32IEEEPolynomial = 0xedb88320u;

        // Castagnoli's polynomial, used in iSCSI.
        // Has better error detection characteristics than IEEE.
        // https://dx.doi.org/10.1109/26.231911
        private const uint Crc32CastagnoliPolynomial = 0x82f63b78;

        public static readonly uint[] Crc32IEEETable = CreateCrcTable(Crc32IEEEPolynomial);

        public static readonly uint[] Crc32CastagnoliTable = CreateCrcTable(Crc32CastagnoliPolynomial);

        public static uint Calculate(string text, uint[] crc32Table = null)
        {
            byte[] data = Encoding.ASCII.GetBytes(text);
            return Calculate(data, crc32Table);
        }

        public static uint Calculate(byte[] buffer, uint[] crc32Table = null)
        {
            return Calculate(0, buffer, 0, buffer.Length, crc32Table);
        }

        public static uint Calculate(uint checksum, byte[] buffer, int offset, int length, uint[] crc32Table = null)
        {
            if (crc32Table == null)
            {
                crc32Table = Crc32IEEETable;
            }

            checksum ^= 0xffffffffU;

            while (length >= 16)
            {
                uint a = crc32Table[(3 * 256) + buffer[offset + 12]] ^
                         crc32Table[(2 * 256) + buffer[offset + 13]] ^
                         crc32Table[(1 * 256) + buffer[offset + 14]] ^
                         crc32Table[(0 * 256) + buffer[offset + 15]];

                uint b = crc32Table[(7 * 256) + buffer[offset + 8]] ^
                         crc32Table[(6 * 256) + buffer[offset + 9]] ^
                         crc32Table[(5 * 256) + buffer[offset + 10]] ^
                         crc32Table[(4 * 256) + buffer[offset + 11]];

                uint c = crc32Table[(11 * 256) + buffer[offset + 4]] ^
                         crc32Table[(10 * 256) + buffer[offset + 5]] ^
                         crc32Table[(9 * 256) + buffer[offset + 6]] ^
                         crc32Table[(8 * 256) + buffer[offset + 7]];

                uint d = crc32Table[(15 * 256) + ((byte)checksum ^ buffer[offset])] ^
                         crc32Table[(14 * 256) + ((byte)(checksum >> 8) ^ buffer[offset + 1])] ^
                         crc32Table[(13 * 256) + ((byte)(checksum >> 16) ^ buffer[offset + 2])] ^
                         crc32Table[(12 * 256) + ((checksum >> 24) ^ buffer[offset + 3])];

                checksum = d ^ c ^ b ^ a;
                offset += 16;
                length -= 16;
            }

            while (--length >= 0)
            {
                checksum = crc32Table[(checksum ^ buffer[offset++]) & 0xFF] ^ (checksum >> 8);
            }

            checksum ^= 0xffffffffU;

            return checksum;
        }

        private static uint[] CreateCrcTable(uint polynomial)
        {
            uint[] table = new uint[16 * 256];

            for (uint i = 0; i < 256; i++)
            {
                uint res = i;

                for (int t = 0; t < 16; t++)
                {
                    for (int k = 0; k < 8; k++)
                    {
                        res = (res & 1) == 1
                            ? polynomial ^ (res >> 1)
                            : (res >> 1);
                    }

                    table[(t * 256) + i] = res;
                }
            }

            return table;
        }
    }
}
