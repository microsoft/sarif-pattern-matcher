// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Sarif.PatternMatcher
{
    public class SimpleFix
    {
        /// <summary>
        /// Gets or sets a string value that describes this fix. This property
        /// will be used to label the fix in the IDE UX for invoking replacement
        /// operations.
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// Gets or sets a string value representing text that should be replaced
        /// in the match. This string can contain named arguments, e.g.,
        /// '{scanTarget}'. These arguments will be expanded before the replacement.
        /// </summary>
        public string Find { get; set; }

        /// <summary>
        /// Gets or sets a string value representing text that should injected into the match.
        /// This string can contain named arguments, e.g., '{scanTarget}'. These
        /// arguments will be expanded before the replacement.
        /// </summary>
        public string ReplaceWith { get; set; }
    }
}
