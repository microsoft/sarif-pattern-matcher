// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

using Microsoft.Strings.Interop;

namespace Microsoft.RE2.Managed
{
    public class RE2Regex : IRegex
    {
        public static IRegex Instance = new RE2Regex();
        public static TimeSpan DefaultTimeout = TimeSpan.FromMilliseconds(int.MaxValue - 1);

        private RE2Regex()
        {
        }

        public bool IsMatch(FlexString input, string pattern, RegexOptions options = RegexOptions.None, TimeSpan timeout = default, string captureGroup = null)
        {
            return Regex2.IsMatch(input, pattern, options);
        }

        public FlexMatch Match(FlexString input, string pattern, RegexOptions options = RegexOptions.None, TimeSpan timeout = default, string captureGroup = null)
        {
            int lastUtf8Index = 0;
            int lastUtf16Index = 0;

            return ToFlex(Regex2.Match(input, pattern, options), input, ref lastUtf8Index, ref lastUtf16Index);
        }

        public IEnumerable<FlexMatch> Matches(FlexString input, string pattern, RegexOptions options = RegexOptions.None, TimeSpan timeout = default, string captureGroup = null)
        {
            Timeout t =
                timeout == default
                    ? Timeout.Unlimited
                    : Timeout.Start(timeout);

            int lastUtf8Index = 0;
            int lastUtf16Index = 0;

            foreach (Match2 match in Regex2.Matches(input, pattern, options, t))
            {
                yield return ToFlex(match, input, ref lastUtf8Index, ref lastUtf16Index);
            }
        }

        public bool Matches(string pattern, string text, out List<Dictionary<string, FlexMatch>> matches)
        {
            return Regex2.Matches(pattern, text, out matches);
        }

        private FlexMatch ToFlex(Match2 match, FlexString input, ref int lastUtf8Index, ref int lastUtf16Index)
        {
            if (match.Index == -1) { return new FlexMatch() { Success = false, Index = -1, Length = -1, Value = null }; }

            // Get the value using the UTF-8 string and indices
            String8 value = ((String8)input).Substring(match.Index, match.Length);

            // Map the UTF-8 index to UTF-16
            int mappedIndex = String8.Utf8ToUtf16(match.Index, input, lastUtf8Index, lastUtf16Index);
            lastUtf8Index = match.Index;
            lastUtf16Index = mappedIndex;

            // Map the length to UTF-16
            int mappedEnd = String8.Utf8ToUtf16(match.Index + match.Length, input, lastUtf8Index, lastUtf16Index);
            int mappedLength = mappedEnd - mappedIndex;

            // Return the UTF-16 indices but the UTF-8 derived value
            return new FlexMatch() { Success = true, Index = mappedIndex, Length = mappedLength, Value = value };
        }
    }
}
