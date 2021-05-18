// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

using Microsoft.Strings.Interop;

namespace Microsoft.RE2.Managed
{
    /// <summary>
    /// <para>
    ///  Regex2 provides Regular Expression methods using the RE2 C++ library underneath.
    ///  See https://github.com/google/re2.
    /// </para>
    /// <para>
    ///  RE2 uses an NFA (non-deterministic finite automata) implementation of regular expression matching,
    ///  instead of the backtracking-based approach that .NET (and Perl, and many other implementations) use.
    ///  See https://swtch.com/~rsc/regexp/regexp1.html for a discussion of the algorithmic differences.
    /// </para>
    /// <para> This means that RE2 provides consistently linear matching times on the input size for a given expression.</para>
    /// <para>
    ///  RE2 supports most of the same constructs as .NET Regular Expressions, but not:
    ///    - Named Groups ["(?&lt;groupName&gt;...)"]
    ///    - Backreferences [ "\k(...)"].
    /// </para>
    /// </summary>
    /// <remarks>
    ///  This class is static, because we need to cache the parsed Regular Expressions within RE2 for performance,
    ///  and it's not pleasant to maintain a native instance object tied to a specific set of parsed expressions.
    /// </remarks>
    public static class Regex2
    {
        // We keep RE2 parsed Regexes for reuse. They can only be used by one thread at a time (they track match state),
        // so we want one copy per concurrent thread to avoid contention. This ConcurrentBag allows us to keep a set of
        // these caches which threads 'check out' and 'check in' so that they are reused as threads are discarded.
        internal static readonly ConcurrentBag<ParsedRegexCache> ParsedRegexes = new ConcurrentBag<ParsedRegexCache>();

        private const string NamedGroupExpression = @"\(\?<[^>]+>";

        // Track how many RegexCaches (the Dictionaries) we build; it should be bounded at the number of concurrent threads,
        // even if threads are destroyed and created.
        private static int _regexThreadCacheCount;

        public static int RegexThreadCacheCount => _regexThreadCacheCount;

        /// <summary>
        /// Gets or sets NativeLibraryFolderPath.
        /// </summary>
        /// <remarks>
        /// NativeLibraryFolderPath may be set before using Regex2 to change the path
        /// from which the native library is loaded.
        /// </remarks>
        public static string NativeLibraryFolderPath { get; set; }

        public static string RemoveNamedGroups(string expression)
        {
            if (string.IsNullOrEmpty(expression)) { return string.Empty; }

            // If regex has no named groups, return it as-is
            if (expression.IndexOf("(?<") == -1) { return expression; }

            // Replace any '(?<groupName>' with '(' and return
            return Regex.Replace(expression, NamedGroupExpression, "(");
        }

        /// <summary>
        ///  Run the C++ side test method. Use to quickly test native interop or behavior.
        /// </summary>
        public static unsafe void Test()
        {
            NativeMethods.Test();
        }

        /// <summary>
        ///  Match a Regular Expression against a UTF-8 converted body of text, starting at the desired index.
        /// </summary>
        /// <param name="text">UTF-8 converted text to match.</param>
        /// <param name="expression">Regular Expression to match; must not contain named groups or backreferences.</param>
        /// <param name="options">RegexOptions to use.</param>
        /// <param name="timeout">Timeout for runtime (checked between matches only).</param>
        /// <param name="fromIndex">Index in text to start searching from (used to resume matching).</param>
        /// <returns>IEnumerable of matches found.</returns>
        public static IEnumerable<Match2> Matches(String8 text,
                                                  string expression,
                                                  RegexOptions options = RegexOptions.None,
                                                  Timeout timeout = default,
                                                  int fromIndex = 0)
        {
            ParsedRegexCache cache = null;
            try
            {
                cache = CheckoutCache();

                // Allocate an array to contain matches
                var matches = new Match2[32];

                // Get or Cache the Regex on the native side and retrieve an index to it
                int expressionIndex = BuildRegex(cache, expression, options, -1);

                while (true)
                {
                    // Find the next batch of matches
                    int matchCount = Matches(expressionIndex, text, fromIndex, matches, timeout.RemainingMilliseconds);

                    // Return found matches
                    for (int i = 0; i < matchCount; ++i)
                    {
                        yield return matches[i];
                    }

                    // If match array wasn't filled, we're done
                    if (matchCount < matches.Length) { break; }

                    // If the timeout expired, we're done
                    if (timeout.IsExpired)
                    {
                        break;
                    }

                    // Otherwise, resume just after the last match
                    fromIndex = matches[matchCount - 1].Index + 1;
                }
            }
            finally
            {
                CheckinCache(cache);
            }
        }

        /// <summary>
        ///  Return whether text contains a match for the given Regular Expression.
        /// </summary>
        /// <param name="text">UTF8 text to search within.</param>
        /// <param name="expression">Regular Expression to match.</param>
        /// <param name="options">RegexOptions to use.</param>
        /// <param name="timeout">Timeout in ms.</param>
        /// <returns>True if expression match found in text, False otherwise.</returns>
        public static bool IsMatch(String8 text, string expression, RegexOptions options = RegexOptions.None, Timeout timeout = default)
        {
            return Match(text, expression, options, timeout).Index != -1;
        }

        /// <summary>
        ///  Return the first match for the given Regular Expression, index -1 if no matches.
        /// </summary>
        /// <param name="text">UTF8 text to search within.</param>
        /// <param name="expression">Regular Expression to match.</param>
        /// <param name="options">RegexOptions to use.</param>
        /// <param name="timeout">Timeout in ms.</param>
        /// <returns>First Match found in text; index will be -1 if no matches found.</returns>
        public static Match2 Match(String8 text, string expression, RegexOptions options = RegexOptions.None, Timeout timeout = default)
        {
            ParsedRegexCache cache = null;
            try
            {
                cache = CheckoutCache();
                var matches = new Match2[1];
                int expressionIndex = BuildRegex(cache, expression, options, -1);

                int countFound = Matches(expressionIndex, text, 0, matches, timeout.RemainingMilliseconds);
                if (countFound == 0)
                {
                    matches[0].Index = -1;
                    matches[0].Length = -1;
                }

                return matches[0];
            }
            finally
            {
                CheckinCache(cache);
            }
        }

        /// <summary>
        /// Release all cached Regular Expressions.
        /// </summary>
        public static void ClearRegexes()
        {
            NativeMethods.ClearRegexes();
            while (!ParsedRegexes.IsEmpty)
            {
                ParsedRegexes.TryTake(out ParsedRegexCache _);
                Interlocked.Decrement(ref _regexThreadCacheCount);
            }
        }

        public static unsafe bool Matches(string pattern, string text, out List<Dictionary<string, FlexMatch>> matches, long maxMemoryInBytes)
        {
            ParsedRegexCache cache = null;
            try
            {
                if (string.IsNullOrEmpty(text))
                {
                    matches = null;
                    return false;
                }

                cache = CheckoutCache();

                // Get or Cache the Regex on the native side and retrieve an index to it
                int expressionIndex = BuildRegex(cache, pattern, RegexOptions.None, maxMemoryInBytes);

                byte[] buffer = null;
                var expression8 = String8.Convert(text, ref buffer);
                int[] indexMap = GetMapOfUtf8ToUtf16ByteIndices(buffer);

                fixed (byte* textUtf8BytesPtr = expression8.Array)
                {
                    MatchesCaptureGroupsOutput* output;

                    // Use RE2 to search the text for the pattern.
                    NativeMethods.MatchesCaptureGroups(
                        expressionIndex,
                        new String8Interop(textUtf8BytesPtr, expression8.Index, expression8.Length),
                        &output);

                    // Build SubmatchIndex to GroupName map
                    var submatchIndex2GroupName = new Dictionary<int, string>(output->NumGroupNames);
                    for (int i = 0; i < output->NumGroupNames; i++)
                    {
                        string groupName = Encoding.UTF8.GetString(output->GroupNamesBuffer, output->GroupNameHeaders[i].Length);
                        output->GroupNamesBuffer += output->GroupNameHeaders[i].Length;
                        submatchIndex2GroupName[output->GroupNameHeaders[i].Index] = groupName;
                    }

                    // Build matches output.
                    matches = new List<Dictionary<string, FlexMatch>>(output->NumMatches);

                    // Iterate through each match.
                    for (int matchIndex = 0; matchIndex < output->NumMatches; matchIndex++)
                    {
                        var newSubmatchIndices = new Dictionary<string, FlexMatch>(output->NumSubmatches);
                        matches.Add(newSubmatchIndices);

                        // Handle each submatch of the match.
                        for (int submatchIndex = 0; submatchIndex < output->NumSubmatches; submatchIndex++)
                        {
                            Submatch submatchRe2 = output->Matches[matchIndex][submatchIndex];
                            int submatchUtf8BytesStartIndex = submatchRe2.Index;
                            int submatchUtf8BytesLength = submatchRe2.Length;

                            // Convert submatch to string and UTF-16 indices.
                            string submatchString;
                            int submatchUtf16BytesStartIndex;
                            int submatchUtf16BytesLength;
                            if ((submatchUtf8BytesStartIndex == -1) && (submatchUtf8BytesLength == -1))
                            {
                                // This is a optional group that was not matched.
                                submatchString = null;
                                submatchUtf16BytesStartIndex = -1;
                                submatchUtf16BytesLength = -1;
                            }
                            else if (submatchUtf8BytesStartIndex >= expression8.Length)
                            {
                                // This match occured past the end of the string.
                                submatchString = null;
                                submatchUtf16BytesStartIndex = text.Length;
                                submatchUtf16BytesLength = 0;
                            }
                            else
                            {
                                // This is a regular match.
                                submatchString = Encoding.UTF8.GetString(buffer, submatchUtf8BytesStartIndex, submatchUtf8BytesLength);
                                submatchUtf16BytesStartIndex = indexMap[submatchUtf8BytesStartIndex];
                                submatchUtf16BytesLength = submatchString.Length;
                            }

                            // Create FlexMatch.
                            var flexMatch = new FlexMatch()
                            {
                                Success = true,
                                Index = submatchUtf16BytesStartIndex,
                                Length = submatchUtf16BytesLength,
                                Value = submatchString,
                            };

                            // Associate submatches with group names or indices.
                            if (submatchIndex2GroupName.ContainsKey(submatchIndex))
                            {
                                string groupName = submatchIndex2GroupName[submatchIndex];
                                newSubmatchIndices[groupName] = flexMatch;
                            }
                            else
                            {
                                newSubmatchIndices[submatchIndex.ToString()] = flexMatch;
                            }
                        }
                    }

                    // Free C++ resources.
                    NativeMethods.MatchesCaptureGroupsDispose(output);
                }

                return matches.Count > 0;
            }
            finally
            {
                CheckinCache(cache);
            }
        }

        private static int[] GetMapOfUtf8ToUtf16ByteIndices(byte[] utf8Bytes)
        {
            int[] indexMap = new int[utf8Bytes.Length];

            int utf8ByteIndex = 0;
            int utf16ByteIndex = 0;
            while (utf8ByteIndex < utf8Bytes.Length)
            {
                indexMap[utf8ByteIndex] = utf16ByteIndex;
                GetCharacterSizeInBytes(utf8Bytes[utf8ByteIndex], out int utf8CharacterSizeInBytes, out int utf16CharacterSizeInBytes);
                utf8ByteIndex += utf8CharacterSizeInBytes;
                utf16ByteIndex += utf16CharacterSizeInBytes;
            }

            return indexMap;
        }

        private static void GetCharacterSizeInBytes(byte b, out int utf8CharacterSizeInBytes, out int utf16CharacterSizeInBytes)
        {
            if (b < 0x80)
            {
                utf8CharacterSizeInBytes = 1;
                utf16CharacterSizeInBytes = 1;
            }
            else if (b < 0xC0)
            {
                throw new Exception($"found unexpected byte when decoding UTF-8: {b}");
            }
            else if (b < 0xE0)
            {
                utf8CharacterSizeInBytes = 2;
                utf16CharacterSizeInBytes = 1;
            }
            else if (b < 0xF0)
            {
                utf8CharacterSizeInBytes = 3;
                utf16CharacterSizeInBytes = 1;
            }
            else if (b < 0xF8)
            {
                utf8CharacterSizeInBytes = 4;
                utf16CharacterSizeInBytes = 2;
            }
            else
            {
                throw new Exception($"found unexpected byte when decoding UTF-8: {b}");
            }
        }

        // Retrieve a Regex Cache before each match to reuse parsed Regex objects.
        // We don't keep a threadlocal one so that they aren't leaked if threads are discarded.
        private static ParsedRegexCache CheckoutCache()
        {
            ParsedRegexCache cache;
            if (!ParsedRegexes.TryTake(out cache))
            {
                Interlocked.Increment(ref _regexThreadCacheCount);
                cache = new ParsedRegexCache();
            }

            return cache;
        }

        // Return the Regex Cache after use via a finally block.
        private static void CheckinCache(ParsedRegexCache cache)
        {
            if (cache != null) { ParsedRegexes.Add(cache); }
        }

        // Get the integer ID of the cached copy of the Regex from the native side; cache it if it hasn't been parsed.
        private static unsafe int BuildRegex(ParsedRegexCache cache, string expression, RegexOptions options, long maxMemory)
        {
            if (string.IsNullOrEmpty(expression)) { throw new ArgumentNullException(nameof(expression)); }

            try
            {
                var key = Tuple.Create<string, RegexOptions>(expression, options);
                int expressionIndex;

                if (!cache.TryGetValue(key, out expressionIndex))
                {
                    // Remove named groups from the expression (on add only, so once per Regex only)
                    expression = RemoveNamedGroups(expression);

                    byte[] buffer = null;
                    var expression8 = String8.Convert(expression, ref buffer);

                    // The native BuildRegex code is thread-safe for creating compiled expressions.
                    fixed (byte* expressionPtr = expression8.Array)
                    {
                        expressionIndex = NativeMethods.BuildRegex(new String8Interop(expressionPtr, expression8.Index, expression8.Length), (int)options, maxMemory);
                    }

                    // Throw if RE2 couldn't parse the regex.
                    // Error Text is native allocated and so not returned; it's written to the console by RE2.
                    if (expressionIndex == -1)
                    {
                        throw new ArgumentException($"RE2 could not parse regular expression \"{expression}\".");
                    }

                    // Throw if RE2 couldn't support a passed RegexOption.
                    if (expressionIndex == -2)
                    {
                        throw new ArgumentException($"RE2 doesn't support a passed RegexOption. Supported Options: Singleline, IgnoreCase. Options passed: {options}");
                    }

                    cache[key] = expressionIndex;
                }

                return expressionIndex;
            }
            catch (DllNotFoundException ex)
            {
                // Throw a clearer exception if RE2.Native.*.dll wasn't found in any of the DLL loading paths.
                throw new InvalidOperationException($"RE2.Native.*.dll was not found. It's required for RE2.Managed to run. Place RE2.Native.*.dll next to RE2.Managed.dll in '{Assembly.GetExecutingAssembly().Location}'. HR: {ex.HResult}", ex);
            }
        }

        /// <summary>
        ///  Match a Regular Expression against a UTF-8 converted body of text, starting at the desired index.
        /// </summary>
        /// <param name="expressionIndex">Cached Index of Regular Expression to match; must not contain named groups or backreferences.</param>
        /// <param name="text">UTF-8 converted text to match.</param>
        /// <param name="fromIndex">Index in text to start searching from (used to resume matching).</param>
        /// <param name="matches">MatchPosition array to fill with matches found.</param>
        /// <param name="timeoutMs">Timeout in ms.</param>
        /// <returns>Count of matches found in array.</returns>
        private static unsafe int Matches(int expressionIndex, String8 text, int fromIndex, Match2[] matches, int timeoutMs)
        {
            // Validate String8 text is allocated and in range
            if (text.Length == 0) { return 0; }
            if (text.Array == null) { throw new ArgumentNullException("text.Array"); }
            if (text.Index < 0 || text.Length < 0 || text.Index + text.Length > text.Array.Length) { throw new ArgumentOutOfRangeException(nameof(text)); }

            // Validate fromIndex
            if (fromIndex < 0 || fromIndex >= text.Array.Length) { throw new ArgumentOutOfRangeException(nameof(fromIndex)); }

            // Validate matches
            if (matches == null) { throw new ArgumentNullException(nameof(matches)); }
            if (matches.Length == 0) { throw new ArgumentException("Matches length shoul be greater than zero", nameof(matches)); }

            // Validate timeout (just return immediately if timeout expired)
            if (timeoutMs < 0) { return 0; }

            int countFound;

            fixed (byte* textPtr = text.Array)
            {
                fixed (Match2* matchesPtr = matches)
                {
                    var text8i = new String8Interop(textPtr, text.Index, text.Length);
                    countFound = NativeMethods.Matches(expressionIndex, text8i, fromIndex, matchesPtr, matches.Length, timeoutMs);
                }
            }

            // Throw if native side found expressionIndex invalid
            return countFound < 0
                ? throw new ArgumentOutOfRangeException($"expressionIndex (was: {expressionIndex}, nativeCount: {-countFound})")
                : countFound;
        }

        /// <summary>
        ///  RE2 Parsed Regex instances need to be cached, as they're slow to parse.
        ///  RE2.Native returns an integer index to refer to the cached regexes.
        ///  This class tracks Regexes we've had RE2 parse before to reuse them.
        /// </summary>
        internal class ParsedRegexCache : Dictionary<Tuple<string, RegexOptions>, int>
        { }
    }
}
