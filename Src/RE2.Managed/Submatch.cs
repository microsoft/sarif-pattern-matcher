// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;

namespace Microsoft.RE2.Managed
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct Submatch
    {
        public int Index;
        public int Length;

        /// <summary>
        /// Capturing groups may be marked as optional. If they are optional and not found,
        /// then they are handled specially.
        /// </summary>
        ///
        /// <returns>Boolean indicating if this is an optional group that was not found.</returns>
        public bool IsOptionalGroupAndNotFound()
        {
            return (this.Index == -1) && (this.Length == -1);
        }
    }
}
