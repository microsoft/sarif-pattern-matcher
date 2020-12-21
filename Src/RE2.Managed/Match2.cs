// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;

namespace Microsoft.RE2.Managed
{
    /// <summary>
    ///  Represents the UTF8 position and length of a Regular Expression match within text.
    /// </summary>
    /// <remarks>
    /// Matches RE2.Native\Match2.h and must maintain identical layout.
    /// </remarks>
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct Match2
    {
        public int Index;
        public int Length;
    }
}
