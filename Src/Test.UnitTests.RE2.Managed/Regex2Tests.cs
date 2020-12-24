// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Strings.Interop;

using Xunit;

namespace Microsoft.RE2.Managed
{
    public class Regex2Tests
    {
        static Regex2Tests()
        {
            // Ensure Test harness is running x64
            Regex2.NativeLibraryFolderPath = @"runtimes\win-x64\native";
        }

        [Fact]
        public void Regex2_Basics()
        {
            byte[] buffer = null, buffer2 = null;
            var sample = String8.Convert("using Microsoft.VisualStudio.TestTools.UnitTesting;", ref buffer2);

            // Null and Empty
            Assert.Throws<ArgumentException>(() => Regex2.IsMatch(sample, null));
            Assert.Throws<ArgumentException>(() => Regex2.IsMatch(sample, ""));
            Assert.False(Regex2.IsMatch(String8.Empty, "[A-Z]"));
            Assert.Throws<ArgumentException>(() => Regex2.Matches(sample, null).FirstOrDefault());
            Assert.Throws<ArgumentException>(() => Regex2.Matches(sample, "").FirstOrDefault());

            // Basic Expressions
            Assert.True(Regex2.IsMatch(String8.Convert("Interesting", ref buffer), "[A-Z]"));
            Assert.False(Regex2.IsMatch(String8.Convert("1234567890", ref buffer), "[A-Z]"));

            // Regex Parse Errors
            Assert.Throws<ArgumentException>(() => Regex2.IsMatch(sample, "(unclosedParen"));
            Assert.Throws<ArgumentException>(() => Regex2.IsMatch(sample, "[unclosedBrace"));
            Assert.Throws<ArgumentException>(() => Regex2.IsMatch(sample, "(['\"])matching quote backreference\\k1"));

            // Corrected Regex Parse Errors (named groups have names removed by Regex2
            Assert.True(Regex2.IsMatch(sample, "(?<namedGroup>Tes)tTools"));

            // Match Index and Length, Multiple Matches
            Assert.Equal("(5, 11: ' Microsoft.'), (15, 14: '.VisualStudio.'), (28, 11: '.TestTools.'), (38, 13: '.UnitTesting;')", string.Join(", ", Regex2.Matches(sample, "[ \\.][^\\.]+[\\.;]").Select((m) => MatchToString(m, sample))));

            // Overlapping Matches
            Assert.Equal("(5, 46: ' Microsoft.VisualStudio.TestTools.UnitTesting;'), (15, 36: '.VisualStudio.TestTools.UnitTesting;'), (28, 23: '.TestTools.UnitTesting;'), (38, 13: '.UnitTesting;')", string.Join(", ", Regex2.Matches(sample, "[ \\.].+[\\.;]").Select((m) => MatchToString(m, sample))));

            // Internal String8.String8 range checks
            Assert.Throws<ArgumentNullException>(() => Regex2.IsMatch(new String8(null, sample.Index, sample.Length), "[A-Z]"));
            Assert.Throws<ArgumentOutOfRangeException>(() => Regex2.IsMatch(new String8(sample.Array, -1, sample.Length), "[A-Z]"));
            Assert.Throws<ArgumentOutOfRangeException>(() => Regex2.IsMatch(new String8(sample.Array, 0, sample.Length + 1), "[A-Z]"));
            Assert.Throws<ArgumentOutOfRangeException>(() => Regex2.IsMatch(new String8(sample.Array, sample.Length - 2, 3), "[A-Z]"));

            // IgnoreCase option
            Assert.True(Regex2.IsMatch(sample, @"[^\.]+Tools"));
            Assert.False(Regex2.IsMatch(sample, @"[^\.]+TOOLS"));
            Assert.True(Regex2.IsMatch(sample, @"[^\.]+TOOLS", RegexOptions.IgnoreCase));

            // Singleline option
            var moreLines = String8.Convert("using Microsoft\r\n\t.VisualStudio\r\n\t.TestTools\r\n\t.UnitTesting;", ref buffer);
            Assert.False(Regex2.IsMatch(moreLines, "using (.+)VisualStudio"));
            Assert.True(Regex2.IsMatch(moreLines, "using (.+)VisualStudio", RegexOptions.Singleline));

            // Multiple options
            Assert.True(Regex2.IsMatch(moreLines, "using (.+)VISUALSTUDIO", RegexOptions.CultureInvariant | RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline));

            // Ignored options don't throw and work with other options
            Assert.False(Regex2.IsMatch(sample, @"[^\.]+TOOLS", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture));
            Assert.True(Regex2.IsMatch(sample, @"[^\.]+TOOLS", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture));

            // Unsupported Options throw
            Assert.Throws<ArgumentException>(() => Regex2.IsMatch(sample, @"[^\.]+Tools", RegexOptions.Multiline));
            Assert.Throws<ArgumentException>(() => Regex2.IsMatch(sample, @"[^\.]+Tools", RegexOptions.IgnorePatternWhitespace));
            Assert.Throws<ArgumentException>(() => Regex2.IsMatch(sample, @"[^\.]+Tools", RegexOptions.RightToLeft));
            Assert.Throws<ArgumentException>(() => Regex2.IsMatch(sample, @"[^\.]+Tools", RegexOptions.ECMAScript));

            // Insensitive case
            Assert.True(Regex2.IsMatch(String8.Convert("aA", ref buffer), "(?i)A(?-i)A"));
            Assert.True(Regex2.IsMatch(String8.Convert("AA", ref buffer), "(?i)A(?-i)A"));
            Assert.False(Regex2.IsMatch(String8.Convert("aa", ref buffer), "(?i)A(?-i)A"));
            Assert.False(Regex2.IsMatch(String8.Convert("Aa", ref buffer), "(?i)A(?-i)A"));
        }

        [Fact]
        public void Regex2_Timeout()
        {
            byte[] buffer = null;
            var sample = String8.Convert("using Microsoft.VisualStudio.TestTools.UnitTesting;", ref buffer);

            // Long timeout: Verify all matches returned
            var timeout = Timeout.Start(TimeSpan.FromSeconds(10));
            Assert.Equal(51, Regex2.Matches(sample, ".", RegexOptions.None, timeout).Count());
            Assert.False(timeout.IsExpired);

            // Tiny timeout: Verify early stop
            timeout = Timeout.Start(TimeSpan.FromTicks(1));
            Assert.NotEqual(51, Regex2.Matches(sample, ".", RegexOptions.None, timeout).Count());
            Assert.True(timeout.IsExpired);
        }

        [Fact]
        public void Regex2_MultiThreaded()
        {
            const string content = @"
{
    ""title"": ""Interesting"",
    ""message"": ""Nothing Found""
}";
            Parallel.For(0, 1000, (_) =>
            {
                int count = 0;

                byte[] buffer = null;
                var content8 = String8.Convert(content, ref buffer);
                foreach (Match2 match in Regex2.Matches(content8, "\\\"message\\\": ?\\\"[^\\\"]*\\\""))
                {
                    count++;
                }
            });
        }

        [Fact]
        public void Regex2_ThreadCycling()
        {
            int threadCount = Environment.ProcessorCount;
            var threads = new Thread[threadCount];

            for (int iteration = 0; iteration < 50; ++iteration)
            {
                for (int index = 0; index < threads.Length; ++index)
                {
                    var t = new Thread(new ThreadStart(Run))
                    {
                        IsBackground = true
                    };
                    t.Start();
                    threads[index] = t;
                }

                for (int index = 0; index < threads.Length; ++index)
                {
                    threads[index].Join();
                    threads[index] = null;
                }
            }

            Trace.Write($"{Regex2.RegexThreadCacheCount} Regex caches created across up to {threads.Length} threads.");

            // This test code isn't strictly isolated from other cache activity provoked by other tests.
            // And so we'll loosen this assert in order to account for the possibility that other test
            // threads have retrieved a cahce and been preempted while this test is executing.
            Assert.True(Regex2.RegexThreadCacheCount <= threadCount * 2);
        }

        [Fact]
        public void Regex2_MatchAndClear()
        {
            byte[] buffer = null;

            // Matching should create one parsed regex
            Assert.True(Regex2.IsMatch(String8.Convert("aA", ref buffer), "(?i)A(?-i)A"));
            Assert.Single(Regex2.ParsedRegexes);

            // Same match should re-use
            Assert.True(Regex2.IsMatch(String8.Convert("AA", ref buffer), "(?i)A(?-i)A"));
            Assert.Single(Regex2.ParsedRegexes);

            // Clear should remove parsed regex
            Regex2.ClearRegexes();
            Assert.Empty(Regex2.ParsedRegexes);

            // Matching should work again
            Assert.True(Regex2.IsMatch(String8.Convert("AA", ref buffer), "(?i)A(?-i)A"));
            Assert.Single(Regex2.ParsedRegexes);
        }

        private string MatchToString(Match2 match, String8 content)
        {
            return $"({match.Index}, {match.Length}: '{content.Substring(match.Index, match.Length)}')";
        }

        private static void Run()
        {
            const string content = @"
{
    ""title"": ""Interesting"",
    ""message"": ""Nothing Found""
}";
            for (int i = 0; i < 100; ++i)
            {
                int count = 0;

                byte[] buffer = null;
                var content8 = String8.Convert(content, ref buffer);
                foreach (Match2 match in Regex2.Matches(content8, "\\\"message\\\": ?\\\"[^\\\"]*\\\""))
                {
                    count++;
                }
            }
        }
    }
}
