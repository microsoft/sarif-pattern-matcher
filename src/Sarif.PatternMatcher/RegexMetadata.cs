// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    [Flags]
    public enum RegexMetadata
    {
        /// <summary>
        /// Implicitly, the absence of any regex metadata means
        /// that it is a required match. That is, if the regex
        /// does not exist, the analysis rules halts immediately.
        /// </summary>
        None = 0,

        /// <summary>
        /// Indicates that the regex retrieves an optionally
        /// available value.
        /// </summary>
        Optional = 0x1,

        /// <summary>
        /// Indicates that the regex is potentially shared across
        /// multiple rules (and therefore can be cached).
        /// </summary>
        Shared = 0x2,
    }
}
