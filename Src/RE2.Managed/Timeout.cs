// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher.RE2.Managed
{
    /// <summary>
    /// <para>
    /// Timeout wraps a Stopwatch tracking a start time and a time limit TimeSpan
    /// to allow managing a timeout across method calls easily. This avoids each method
    /// involved in a timeout having a separate StopWatch to calculate remaining time.
    /// </para>
    /// <para>Construct a Timeout with a limit of zero to indicate no timeout.</para>
    /// </summary>
    public struct Timeout
    {
        private Stopwatch Watch { get; set; }
        public TimeSpan Limit { get; }

        /// <summary>
        ///  Timeout.Unlimited is a timeout instance which won't expire
        /// </summary>
        public static Timeout Unlimited = default;

        /// <summary>
        ///  Start a new timeout with the given time limit.
        /// </summary>
        /// <param name="limit">TimeSpan of time limit for this activity</param>
        /// <returns>Timeout to track the limit, starting now.</returns>
        public static Timeout Start(TimeSpan limit)
        {
            return new Timeout(limit);
        }

        /// <summary>
        ///  Construct a Timeout with the given time limit; pass zero for no limit.
        ///  Measuring against the timeout begins when the constructor is called.
        /// </summary>
        /// <param name="limit">TimeSpan for time limit or TimeSpan.Zero for no limit</param>
        private Timeout(TimeSpan limit)
        {
            Limit = limit;
            Watch = Stopwatch.StartNew();
        }

        public bool IsUnlimited => Limit == TimeSpan.Zero;

        /// <summary>
        ///  Returns true if the timeout has expired, false otherwise
        /// </summary>
        public bool IsExpired => !this.IsUnlimited && Watch.Elapsed > Limit;

        /// <summary>
        ///  Return the TimeSpan of time elapsed since the timeout started, if known.
        ///  Will return TimeSpan.Zero for unlimited timeouts.
        /// </summary>
        public TimeSpan Elapsed => Watch == null ? TimeSpan.Zero : Watch.Elapsed;

        /// <summary>
        ///  Return the TimeSpan of time remaining before the time limit, or TimeSpan.Zero if no limit.
        /// </summary>
        public TimeSpan Remaining => IsUnlimited ? TimeSpan.Zero : Limit - Watch.Elapsed;

        /// <summary>
        ///  Returns the number of milliseconds remaining before the time limit is reached, or zero if no limit.
        /// </summary>
        public int RemainingMilliseconds => IsUnlimited ? 0 : (int)((Limit - Watch.Elapsed).TotalMilliseconds);
    }
}
