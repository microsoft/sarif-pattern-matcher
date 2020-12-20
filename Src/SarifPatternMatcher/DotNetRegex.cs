// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

using Strings.Interop;

namespace Sarif.PatternMatcher
{
    /// <summary>
    ///  DotNetRegex is an IRegex implementation calling through to .NET's System.Text.RegularExpressions.Regex.
    /// </summary>
    public class DotNetRegex : IRegex
    {
        public static IRegex Instance = new DotNetRegex();

        internal static TimeSpan DefaultTimeout = TimeSpan.FromMilliseconds(int.MaxValue - 1);

        private DotNetRegex() { }

        public bool IsMatch(FlexString input, string pattern, RegexOptions options = RegexOptions.None, TimeSpan timeout = default, string captureGroup = null)
        {
            if (timeout == default) { timeout = DefaultTimeout; }
            Match match = Regex.Match(input, pattern, options, timeout);
            return match.Success && (captureGroup == null || match.Groups[captureGroup].Success);
        }

        public FlexMatch Match(FlexString input, string pattern, RegexOptions options = RegexOptions.None, TimeSpan timeout = default, string captureGroup = null)
        {
            if (timeout == default) { timeout = DefaultTimeout; }
            return ToFlex(Regex.Match(input, pattern, options, timeout), captureGroup);
        }

        public IEnumerable<FlexMatch> Matches(FlexString input, string pattern, RegexOptions options = RegexOptions.None, TimeSpan timeout = default, string captureGroup = null)
        {
            if (timeout == default) { timeout = DefaultTimeout; }
            foreach (Match m in Regex.Matches(input, pattern, options, timeout))
            {
                yield return ToFlex(m, captureGroup);
            }
        }

        internal static FlexMatch ToFlex(Match match, string captureGroup = null)
        {
            int index = match.Index;
            int length = match.Length;
            string value = match.Value;

            if (captureGroup != null)
            {
                Group group = match.Groups[captureGroup];
                if (group.Success)
                {
                    value = group.Value;
                    index = group.Index;
                    length = group.Length;
                }
            }

            return new FlexMatch() { Success = match.Success, Index = index, Length = length, Value = value };
        }
    }
}
