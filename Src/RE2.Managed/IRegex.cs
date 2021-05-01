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

        bool Matches(string pattern, string text, out List<Dictionary<string, FlexMatch>> matches);
    }
}
