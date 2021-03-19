// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class CmdkeyValidator : ValidatorBase
    {
        internal static CmdkeyValidator Instance;
        internal static IRegex RegexEngine;

        private const string UserRegex = @"\/user:\s*([^\[""'\s`%]{2,})";

        static CmdkeyValidator()
        {
            Instance = new CmdkeyValidator();
            RegexEngine = RE2Regex.Instance;
        }

        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return IsValidStatic(Instance,
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
            if (!groups.TryGetNonEmptyValue("password", out string password))
            {
                return nameof(ValidationState.NoMatch);
            }

            if (IsInvalidPassword(password))
            {
                return nameof(ValidationState.NoMatch);
            }

            string account = ParseExpression(RegexEngine, matchedPattern, UserRegex);
            account = account?.Replace("/user:", string.Empty).Trim();

            fingerprintText = new Fingerprint()
            {
                Account = account,
                Password = password,
            }.ToString();

            // Manual use of the regex against CodeAsData produces highly confident results,
            // so return AuthorizedWarning rather than Unknown.
            return nameof(ValidationState.AuthorizedWarning);
        }

        private static bool IsInvalidPassword(string potentialPassword)
        {
            if (string.IsNullOrWhiteSpace(potentialPassword))
            {
                return true;
            }

            if (potentialPassword.Length < 2)
            {
                return true;
            }

            if (potentialPassword.First() == '$')
            {
                // The command looks like
                // cmdkey /pass: $passwordVariable
                // This is not a match
                return true;
            }

            // The following may be valid characters in the middle of a password, but
            // seeing them on both ends specifically is HIGHLY indicative that a variable
            // was passed into the command.
            if (potentialPassword.First() == '<' && potentialPassword.Last() == '>')
            {
                return true;
            }

            if (potentialPassword.First() == '{' && potentialPassword.Last() == '}')
            {
                return true;
            }

            if (potentialPassword.First() == '(' && potentialPassword.Last() == ')')
            {
                return true;
            }

            if (potentialPassword.First() == '[' && potentialPassword.Last() == ']')
            {
                return true;
            }

            return false;
        }
    }
}
