// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;

namespace Microsoft.RE2.Managed
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct MatchesCaptureGroupsOutput
    {
        public GroupNameHeader* GroupNameHeaders;
        public byte* GroupNamesBuffer;
        public int NumGroupNames;
        public Submatch** Matches;
        public int NumMatches;
        public int NumSubmatches;

        private readonly void* groupNameHeadersCleanupPtr;
        private readonly void* groupNamesBufferCleanupPtr;
        private readonly void* matchesCleanupPtr;
    }
}
