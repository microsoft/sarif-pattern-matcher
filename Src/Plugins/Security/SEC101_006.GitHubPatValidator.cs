// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Octokit;
using Octokit.Internal;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GitHubPatValidator : ValidatorBase
    {
        internal static GitHubPatValidator Instance;

        static GitHubPatValidator()
        {
            Instance = new GitHubPatValidator();
        }

        public static ValidationState IsValidStatic(ref string matchedPattern,
                                                    ref Dictionary<string, string> groups,
                                                    ref string message,
                                                    out ResultLevelKind resultLevelKind,
                                                    out Fingerprint fingerprint)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref message,
                                 out resultLevelKind,
                                 out fingerprint);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     ref Dictionary<string, string> options,
                                                     ref ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options,
                                  ref resultLevelKind);
        }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                               ref Dictionary<string, string> groups,
                                                               ref string message,
                                                               out ResultLevelKind resultLevelKind,
                                                               out Fingerprint fingerprint)
        {
            fingerprint = default;
            resultLevelKind = default;

            if (!groups.TryGetNonEmptyValue("secret", out string pat))
            {
                return ValidationState.NoMatch;
            }

            if (groups.TryGetNonEmptyValue("checksum", out string checksum))
            {
                // TODO: #365 Utilize checksum https://github.com/microsoft/sarif-pattern-matcher/issues/365

                fingerprint = new Fingerprint
                {
                    Secret = matchedPattern,
                    Platform = nameof(AssetPlatform.GitHub),
                };

                return ValidationState.Unknown;
            }

            // It is highly likely we do not have a key if we can't
            // find at least one letter and digit within the pattern.
            if (!ContainsDigitAndChar(pat))
            {
                return ValidationState.NoMatch;
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
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint
            {
                Secret = pat,
                Platform = nameof(AssetPlatform.GitHub),
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string pat = fingerprint.Secret;

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
                // The token is either invalid or has been killed
                return ValidationState.Unauthorized;
            }
            catch (ForbiddenException)
            {
                // The token is valid but doesn't have read/user access. Write only perhaps?
                return ValidationState.Authorized;
            }
            catch (Exception e)
            {
                // ¯\_(ツ)_/¯
                message = $"An unexpected exception was caught attempting to validate PAT: {e.Message}";
                return ValidationState.Unknown;
            }

            return ValidationState.Authorized;
        }
    }
}
