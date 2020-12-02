// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;

using Microsoft.CodeAnalysis.SarifPatternMatcher.Strings;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher
{
    /// <summary>
    ///  CachedDotNetRegex is an IRegex implementation which pre-compiles all Regexes and then
    ///  calls through to .NET's System.Text.RegularExpressions.Regex.
    /// </summary>
    public class CachedDotNetRegex : IRegex
    {
        public static IRegex Instance = new CachedDotNetRegex();

        internal static TimeSpan DefaultTimeout = TimeSpan.FromMilliseconds(int.MaxValue - 1);

        static CachedDotNetRegex()
        {
            RegexCache = new ConcurrentDictionary<Tuple<string, RegexOptions>, Regex>();
        }

        private CachedDotNetRegex() { }

        private static ConcurrentDictionary<Tuple<string, RegexOptions>, Regex> RegexCache { get; }

        public static Regex GetOrCreateRegex(string expression, RegexOptions options)
        {
            var key = Tuple.Create(expression, options);
            return RegexCache.GetOrAdd(key, _ => new Regex(expression, options | RegexOptions.Compiled));
        }

        public bool IsMatch(FlexString input, string pattern, RegexOptions options = RegexOptions.None, TimeSpan timeout = default(TimeSpan), string captureGroup = null)
        {
            // Note: Instance Regex.IsMatch has no timeout overload.
            Regex regex = GetOrCreateRegex(pattern, options);
            Match match = regex.Match(input);
            return match.Success && (captureGroup == null || match.Groups[captureGroup].Success);
        }

        public FlexMatch Match(FlexString input, string pattern, RegexOptions options = RegexOptions.None, TimeSpan timeout = default(TimeSpan), string captureGroup = null)
        {
            // Note: Instance Regex.Match has no timeout overload.
            Regex regex = GetOrCreateRegex(pattern, options);
            return DotNetRegex.ToFlex(regex.Match(input), captureGroup);
        }

        public IEnumerable<FlexMatch> Matches(FlexString input, string pattern, RegexOptions options = RegexOptions.None, TimeSpan timeout = default(TimeSpan), string captureGroup = null)
        {
            if (timeout == default) { timeout = DefaultTimeout; }
            var w = Stopwatch.StartNew();

            Regex regex = GetOrCreateRegex(pattern, options);
            foreach (Match m in regex.Matches(input))
            {
                yield return DotNetRegex.ToFlex(m, captureGroup);

                // Instance Regex.Matches has no overload; check timeout between matches
                // (MatchesCollection *is* lazily computed).
                if (w.Elapsed > timeout) { break; }
            }
        }
    }
}
