// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins
{
    public enum ValidationState
    {
        /// <summary>
        /// Pattern isn't actually a match for secret type.
        /// </summary>
        NoMatch = 0,

        /// <summary>
        /// Pattern is a match but the validity of the secret
        /// can't be determined.
        /// </summary>
        Unknown,

        /// <summary>
        /// Pattern is a match and the secret is conclusively
        /// determined to be invalid (e.g., it is expired).
        /// </summary>
        Invalid,

        /// <summary>
        /// Pattern is a match and the secret is invalid for all
        /// all authorities configured for validation (e.g., it
        /// is expired). The secret may be valid for an authority
        /// that wasn't consulted.
        /// </summary>
        InvalidForConsultedAuthorities,

        /// <summary>
        /// Pattern is a match and the secret is valid.
        /// </summary>
        Valid,
    }
}
