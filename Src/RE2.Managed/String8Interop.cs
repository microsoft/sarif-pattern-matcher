// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;

namespace Microsoft.RE2.Managed
{
    /// <summary>
    ///  Represents a block of UTF8 text in a slice of a byte array.
    /// </summary>
    /// <remarks>
    ///  Matches RE2.Native\String8.h and must maintain identical layout.
    /// </remarks>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct String8Interop
    {
        public byte* Array;
        public int Index;
        public int Length;

        public String8Interop(byte* array, int index, int length)
        {
            this.Array = array;
            this.Index = index;
            this.Length = length;
        }
    }
}
