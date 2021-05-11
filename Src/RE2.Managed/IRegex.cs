// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

using Microsoft.Strings.Interop;

namespace Microsoft.RE2.Managed
{
    /// <summary>
    ///  IRegex is a generic subset of System.Text.RegularExpressions.Regex,
    ///  allowing callers to generically use different Regex engines.
    /// </summary>
    public interface IRegex
    {
        bool IsMatch(FlexString input, string pattern, RegexOptions options = RegexOptions.None, TimeSpan timeout = default, string captureGroup = null);

        FlexMatch Match(FlexString input, string pattern, RegexOptions options = RegexOptions.None, TimeSpan timeout = default, string captureGroup = null);

        IEnumerable<FlexMatch> Matches(FlexString input, string pattern, RegexOptions options = RegexOptions.None, TimeSpan timeout = default, string captureGroup = null);

        /// <summary>
        /// Searches the text for the specified pattern.
        ///
        /// For simplicity, the implementation uses 32-bit signed integers throughout. There is no size-related error checking.
        /// Hence, if some count or size exceeds that (e.g. number of named groups, length of text), there may be silent errors.
        ///
        /// Only <see cref="RE2Regex"/> implements this fully.
        /// </summary>
        ///
        /// <param name="pattern">Pattern to search for in RE2 syntax.</param>
        /// <param name="text">Text to search.</param>
        /// <param name="matches">A list of successive, non-overlapping matches.</param>
        /// <param name="maxMemoryInBytes">Maximum memory in bytes allocated for compiled regular expression.</param>
        /// <returns>A bool indicating if 1 or more matches were found.</returns>
        ///
        /// <example>
        /// <code>
        ///
        /// Input pattern = @"(?P<g1>a)(b)(?P<g2>c)"
        /// Input text    = @"abc abc"
        /// Output = [
        ///     {"0": "abc", "g1": "a", "2": "b", "g2": "c"},
        ///     {"0": "abc", "g1": "a", "2": "b", "g2": "c"}
        /// ]
        ///
        /// Input pattern = @"aa"
        /// Input text    = @"aaaaaa"
        /// Output = [
        ///     {"0": "aa"},
        ///     {"0": "aa"},
        ///     {"0": "aa"}
        /// ]
        ///
        /// </code>
        /// </example>
        bool Matches(string pattern, string text, out List<Dictionary<string, FlexMatch>> matches, long maxMemoryInBytes = -1);
    }
}
