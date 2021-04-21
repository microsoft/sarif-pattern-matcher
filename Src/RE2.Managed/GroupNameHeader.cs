// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;

namespace Microsoft.RE2.Managed
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct GroupNameHeader
    {
        public int Index;
        public int Length;
    }
}
