// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

using IronRe2;

using Microsoft.Strings.Interop;

namespace Microsoft.RE2.Managed
{
    public class IronRE2Regex : IRegex
    {
        public static IronRE2Regex Instance = new IronRE2Regex();
        public static TimeSpan DefaultTimeout = TimeSpan.FromMilliseconds(int.MaxValue - 1);

        static IronRE2Regex()
        {
            RegexCache = new ConcurrentDictionary<Tuple<string, System.Text.RegularExpressions.RegexOptions>, Regex>();
        }

        private IronRE2Regex()
        {
        }

        private static ConcurrentDictionary<Tuple<string, System.Text.RegularExpressions.RegexOptions>, Regex> RegexCache { get; }

        public static Regex GetOrCreateRegex(string pattern, System.Text.RegularExpressions.RegexOptions dotnetRegexOptions)
        {
            Options options = ToOptions(dotnetRegexOptions);
            var key = Tuple.Create(pattern, dotnetRegexOptions);
            return RegexCache.GetOrAdd(key, _ => new Regex(pattern, options));
        }

        public bool IsMatch(FlexString input,
                            string pattern,
                            System.Text.RegularExpressions.RegexOptions regexOptions = 0,
                            TimeSpan timeout = default,
                            string captureGroup = null)
        {
            var tuple = new Tuple<string, System.Text.RegularExpressions.RegexOptions>(pattern, regexOptions);
            Regex regex = GetOrCreateRegex(pattern, regexOptions);
            Match match = regex.Find(input.String8.Array);
            return match.Matched;
        }

        private static Options ToOptions(System.Text.RegularExpressions.RegexOptions dotNetRegexOptions, long maxMemoryInBytes = 256L * 1024L * 1024L)
        {
            bool multiline = dotNetRegexOptions.HasFlag(System.Text.RegularExpressions.RegexOptions.Multiline);
            bool dotNewline = dotNetRegexOptions.HasFlag(System.Text.RegularExpressions.RegexOptions.Singleline);
            bool ignoreCase = dotNetRegexOptions.HasFlag(System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            return new Options
            {
                CaseSensitive = !ignoreCase,
                DotNewline = dotNewline,
                OneLine = !multiline,
                MaxMemory = maxMemoryInBytes,
            };
        }

        public FlexMatch Match(FlexString input,
                               string pattern,
                               System.Text.RegularExpressions.RegexOptions regexOptions = 0,
                               TimeSpan timeout = default,
                               string captureGroup = null)
        {
            var tuple = new Tuple<string, System.Text.RegularExpressions.RegexOptions>(pattern, regexOptions);
            Regex regex = GetOrCreateRegex(pattern, regexOptions);
            Match match = regex.Find(input.String8.Array);

            int lastUtf8Index = 0;
            int lastUtf16Index = 0;
            return ToFlex(match, input, ref lastUtf8Index, ref lastUtf16Index);
        }

        public IEnumerable<FlexMatch> Matches(FlexString input,
                                              string pattern,
                                              System.Text.RegularExpressions.RegexOptions regexOptions = 0,
                                              TimeSpan timeout = default,
                                              string captureGroup = null)
        {
            Timeout t =
                timeout == default
                    ? Timeout.Unlimited
            : Timeout.Start(timeout);

            var tuple = new Tuple<string, System.Text.RegularExpressions.RegexOptions>(pattern, regexOptions);
            Regex regex = GetOrCreateRegex(pattern, regexOptions);

            int lastUtf8Index = 0;
            int lastUtf16Index = 0;

            int index = 0;
            while (index < input.String8.Array.Length)
            {
                Match match = regex.Find(input.String8.Array, index);
                if (!match.Matched) { yield break; }
                index = (int)match.Start + 1;
                yield return ToFlex(match, input, ref lastUtf8Index, ref lastUtf16Index);
            }
        }

        public FlexMatch ToFlex(Match match, FlexString input, ref int lastUtf8Index, ref int lastUtf16Index)
        {
            if (!match.Matched) { return new FlexMatch() { Success = false, Index = -1, Length = -1, Value = null }; }

            // Map the UTF-8 index to UTF-16
            int mappedIndex = String8.Utf8ToUtf16((int)match.Start, input, lastUtf8Index, lastUtf16Index);
            lastUtf8Index = (int)match.Start;
            lastUtf16Index = mappedIndex;

            // Map the length to UTF-16
            int mappedEnd = String8.Utf8ToUtf16((int)(match.Start + match.ExtractedText.Length), input, lastUtf8Index, lastUtf16Index);
            int mappedLength = mappedEnd - mappedIndex;

            // Return the UTF-16 indices but the UTF-8 derived value
            return new FlexMatch() { Success = true, Index = mappedIndex, Length = mappedLength, Value = match.ExtractedText };
        }

        public bool Matches(string pattern, string text, out List<Dictionary<string, FlexMatch>> groupedMatches, long maxMemoryInBytes = 256L * 1024L * 1024L)
        {
            groupedMatches = new List<Dictionary<string, FlexMatch>>();
            var captures = new List<Captures>();

            var tuple = new Tuple<string, System.Text.RegularExpressions.RegexOptions>(pattern, 0);
            Regex regex = GetOrCreateRegex(pattern, 0);

            byte[] bytes = null;
            var string8 = String8.Convert(text, ref bytes);

            int index = 0;

            while (index < string8.Array.Length)
            {
                Captures capture = regex.Captures(string8.Array, index);
                if (!capture.Matched) { break; }
                index = (int)capture.Start + 1;
                captures.Add(capture);
            }

            foreach (Captures capture in captures)
            {
                var current = new Dictionary<string, FlexMatch>(capture.Count);

                Match match;

                int lastUtf8Index = 0;
                int lastUtf16Index = 0;

                match = capture[0];
                current["0"] = ToFlex(match, text, ref lastUtf8Index, ref lastUtf16Index);

                foreach (NamedCaptureGroup namedCaptureGroup in regex.NamedCaptures())
                {
                    int cIndex = regex.FindNamedCapture(namedCaptureGroup.Name);
                    match = capture[cIndex];
                    string groupValue = capture[cIndex].ExtractedText;
                    current[namedCaptureGroup.Name] = ToFlex(match, text, ref lastUtf8Index, ref lastUtf16Index);
                }

                groupedMatches.Add(current);
            }

            return captures.Count > 0;
        }
    }
}
