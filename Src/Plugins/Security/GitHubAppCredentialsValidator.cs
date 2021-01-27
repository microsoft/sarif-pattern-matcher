// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

using Octokit;
using Octokit.Internal;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    internal class GitHubAppCredentialsValidator : ValidatorBase
    {
        internal static GitHubAppCredentialsValidator Instance;

        static GitHubAppCredentialsValidator()
        {
            Instance = new GitHubAppCredentialsValidator();
        }

        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return ValidatorBase.IsValidStatic(Instance,
                                               ref matchedPattern,
                                               ref groups,
                                               ref failureLevel,
                                               ref fingerprint,
                                               ref message);
        }

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetValue("id", out string id) ||
                !groups.TryGetValue("key", out string key))
            {
                return nameof(ValidationState.NoMatch);
            }

            bool oneDigit = false, oneLetter = false;

            foreach (char ch in key)
            {
                if (char.IsDigit(ch)) { oneDigit = true; }
                if (char.IsLetter(ch)) { oneLetter = true; }
                if (oneDigit && oneLetter) { break; }
            }

            if (!oneDigit || !oneLetter)
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint()
            {
                Id = id,
                Key = key,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }
    }
}
