// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;

namespace RE2.Managed
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
        /// <summary>
        ///  Timeout.Unlimited is a timeout instance which won't expire.
        /// </summary>
        public static Timeout Unlimited = default;

        /// <summary>
        /// Initializes a new instance of the <see cref="Timeout"/> struct.
        ///  Measuring against the timeout begins when the constructor is called.
        /// </summary>
        /// <param name="limit">TimeSpan for time limit or TimeSpan.Zero for no limit.</param>
        private Timeout(TimeSpan limit)
        {
            Limit = limit;
            Watch = Stopwatch.StartNew();
        }

        public TimeSpan Limit { get; }

        public bool IsUnlimited => Limit == TimeSpan.Zero;

        /// <summary>
        ///  Gets a value indicating whether timeout has expired.
        /// </summary>
        public bool IsExpired => !this.IsUnlimited && Watch.Elapsed > Limit;

        /// <summary>
        ///  Gets the TimeSpan of time elapsed since the timeout started, if known.
        ///  Will return TimeSpan.Zero for unlimited timeouts.
        /// </summary>
        public TimeSpan Elapsed => Watch == null ? TimeSpan.Zero : Watch.Elapsed;

        /// <summary>
        ///  Gets the TimeSpan of time remaining before the time limit, or TimeSpan.Zero if no limit.
        /// </summary>
        public TimeSpan Remaining => IsUnlimited ? TimeSpan.Zero : Limit - Watch.Elapsed;

        /// <summary>
        ///  Gets a value indicating the milliseconds remaining before the time limit is reached (or zero if no limit).
        /// </summary>
        public int RemainingMilliseconds => IsUnlimited ? 0 : (int)(Limit - Watch.Elapsed).TotalMilliseconds;

        private Stopwatch Watch { get; }

        /// <summary>
        ///  Start a new timeout with the given time limit.
        /// </summary>
        /// <param name="limit">TimeSpan of time limit for this activity.</param>
        /// <returns>Timeout to track the limit, starting now.</returns>
        public static Timeout Start(TimeSpan limit)
        {
            return new Timeout(limit);
        }
    }
}
