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
        private const uint Crc32Polynomial = 0xedb88320u;

        private static readonly uint[] Crc32Table = CreateCrcTable(Crc32Polynomial);

        public static uint Calculate(string text)
        {
            byte[] data = Encoding.ASCII.GetBytes(text);
            return Calculate(data);
        }

        public static uint Calculate(byte[] buffer)
        {
            return Calculate(0, buffer, 0, buffer.Length);
        }

        public static uint Calculate(uint checksum, byte[] buffer, int offset, int length)
        {
            checksum ^= 0xffffffffU;

            while (length >= 16)
            {
                uint a = Crc32Table[(3 * 256) + buffer[offset + 12]] ^
                         Crc32Table[(2 * 256) + buffer[offset + 13]] ^
                         Crc32Table[(1 * 256) + buffer[offset + 14]] ^
                         Crc32Table[(0 * 256) + buffer[offset + 15]];

                uint b = Crc32Table[(7 * 256) + buffer[offset + 8]] ^
                         Crc32Table[(6 * 256) + buffer[offset + 9]] ^
                         Crc32Table[(5 * 256) + buffer[offset + 10]] ^
                         Crc32Table[(4 * 256) + buffer[offset + 11]];

                uint c = Crc32Table[(11 * 256) + buffer[offset + 4]] ^
                         Crc32Table[(10 * 256) + buffer[offset + 5]] ^
                         Crc32Table[(9 * 256) + buffer[offset + 6]] ^
                         Crc32Table[(8 * 256) + buffer[offset + 7]];

                uint d = Crc32Table[(15 * 256) + ((byte)checksum ^ buffer[offset])] ^
                         Crc32Table[(14 * 256) + ((byte)(checksum >> 8) ^ buffer[offset + 1])] ^
                         Crc32Table[(13 * 256) + ((byte)(checksum >> 16) ^ buffer[offset + 2])] ^
                         Crc32Table[(12 * 256) + ((checksum >> 24) ^ buffer[offset + 3])];

                checksum = d ^ c ^ b ^ a;
                offset += 16;
                length -= 16;
            }

            while (--length >= 0)
            {
                checksum = Crc32Table[(checksum ^ buffer[offset++]) & 0xFF] ^ (checksum >> 8);
            }

            checksum ^= 0xffffffffU;

            return checksum;
        }

        private static uint[] CreateCrcTable(uint polynomial)
        {
            var table = new uint[16 * 256];

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
