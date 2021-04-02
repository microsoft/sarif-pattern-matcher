// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public enum ValidationState
    {
        /// <summary>
        /// A default value that reflects an uninitialized state,
        /// (i.e., no useful validation state is available).
        /// </summary>
        None = 0,

        /// <summary>
        /// Validator not found.
        /// </summary>
        ValidatorNotFound,

        /// <summary>
        /// A validator for the current matched pattern returned
        /// an unrecognized state when asked to validate.
        /// </summary>
        ValidatorReturnedIllegalValidationState,

        /// <summary>
        /// Pattern isn't actually a match for secret type.
        /// </summary>
        NoMatch,

        /// <summary>
        /// The validity of the secret can't be determined.
        /// </summary>
        Unknown,

        /// <summary>
        /// The secret is not authorized for access.
        /// </summary>
        Unauthorized,

        /// <summary>
        /// The secret is expired.
        /// </summary>
        Expired,

        /// <summary>
        /// The file or resource is password-protected.
        /// </summary>
        PasswordProtected,

        /// <summary>
        /// The host is unknown.
        /// </summary>
        UnknownHost,

        /// <summary>
        /// Pattern is a match and the secret is invalid for all
        /// all authorities configured for validation (e.g., it
        /// is expired). The secret may be valid for an authority
        /// that wasn't consulted.
        /// </summary>
        InvalidForConsultedAuthorities,

        /// <summary>
        /// Pattern is a match and the secret is valid.
        /// The result should be reported as an error.
        /// </summary>
        AuthorizedError,

        /// <summary>
        /// Pattern is a match and the secret is valid.
        /// The result should be reported as an warning.
        /// </summary>
        AuthorizedWarning,
    }
}
