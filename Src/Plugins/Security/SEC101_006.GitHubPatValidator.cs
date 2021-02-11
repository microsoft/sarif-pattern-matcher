// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.HelpersUtiliesAndExtensions;
using Microsoft.RE2.Managed;

using Octokit;
using Octokit.Internal;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GitHubPatValidator : ValidatorBase
    {
        internal static IRegex RegexEngine;
        internal static GitHubPatValidator Instance;

        private const string PatExpression = "[0-9a-z]{40}";
        private const string PatKey = "PATKEY";

        static GitHubPatValidator()
        {
            Instance = new GitHubPatValidator();
            RegexEngine = RE2Regex.Instance;

            // We perform this work in order to force caching of these
            // expressions (an operation which otherwise can cause
            // threading problems).
            RegexEngine.Match(string.Empty, PatExpression);
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

        public static string IsValidDynamic(ref string fingerprint, ref string message)
        {
            return ValidatorBase.IsValidDynamic(Instance,
                                                ref fingerprint,
                                                ref message);
        }

        public override void MatchCleanup(ref string matchedPattern, ref Dictionary<string, string> groups, ref string failureLevel, ref string fingerprintText, ref string message)
        {
            string pat = RegexEngine.Match(matchedPattern, PatExpression).Value;
            groups.Add(PatKey, pat);
        }

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetNonEmptyValue(PatKey, out string pat))
            {
                return nameof(ValidationState.NoMatch);
            }

            // It is highly likely we do not have a key if we can't
            // find at least one letter and digit within the pattern.
            if (!ContainsDigitAndChar(pat))
            {
                return nameof(ValidationState.NoMatch);
            }

            if (matchedPattern.IndexOf("commit", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("tree", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("blob", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("gist", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("raw", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("repos", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("spec", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("assets", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("using ref", StringComparison.OrdinalIgnoreCase) >= 0 ||
                matchedPattern.IndexOf("githubusercontent.com", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return nameof(ValidationState.NoMatch);
            }

            fingerprintText = new Fingerprint
            {
                PersonalAccessToken = pat,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText, ref string message)
        {
            var fingerprint = new Fingerprint(fingerprintText);
            string pat = fingerprint.PersonalAccessToken;

            try
            {
                var credentials = new Credentials(pat);
                var credentialsStore = new InMemoryCredentialStore(credentials);
                var client = new GitHubClient(new ProductHeaderValue(Guid.NewGuid().ToString()), credentialsStore);

                User user = client.User.Current().GetAwaiter().GetResult();
                string id = user.Login;
                string name = user.Name;

                IReadOnlyList<Organization> orgs = client.Organization.GetAllForCurrent().GetAwaiter().GetResult();
                string orgNames = string.Join(", ", orgs.Select(o => o.Login));

                message = $"the compromised GitHub account '{id} ({name})' has access to the following orgs '{orgNames}'";
            }
            catch (AuthorizationException)
            {
                return nameof(ValidationState.Unauthorized);
            }
            catch (Exception e)
            {
                message = $"An unexpected exception was caught attempting to validate PAT: {e.Message}";
                return nameof(ValidationState.Unknown);
            }

            return nameof(ValidationState.Authorized);
        }
    }
}
