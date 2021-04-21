// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;

namespace Microsoft.RE2.Managed
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct StringUtf8
    {
        public StringUtf8(byte* bytes, int length)
        {
            this.Bytes = bytes;
            this.Length = length;
        }

        public byte* Bytes { get; private set; }

        public int Length { get; private set; }
    }
}
