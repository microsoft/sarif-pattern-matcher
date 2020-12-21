// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Sarif.PatternMatcher
{
    public enum Validation
    {
        /// <summary>
        /// A default value that reflects an uninitialized state,
        /// (i.e., no useful validation state is available).
        /// </summary>
        None = 0,

        /// <summary>
        /// A validator for the current matched pattern
        /// could not be found.
        /// </summary>
        ValidatorNotFound,

        /// <summary>
        /// A validator for the current matched pattern returned
        /// an unrecognized value when asked to validate.
        /// </summary>
        ValidatorReturnedIllegalValue,

        /// <summary>
        /// The current matched pattern is not actually a match
        /// (i.e., the additional validation has revealed that
        /// the match is a false positive).
        /// </summary>
        NoMatch,

        /// <summary>
        /// The current matched pattern is a secret but its
        /// validity could not be determined.
        /// </summary>
        Unknown,

        /// <summary>
        /// The current matched pattern is a secret and it was
        /// determined to be invalid (e.g., it is expired).
        /// </summary>
        Invalid,

        /// <summary>
        /// The current matched pattern is a secret and it is valid.
        /// </summary>
        Valid,
    }
}
