// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class NuGetCredentialsValidator : ValidatorBase
    {
        internal static NuGetCredentialsValidator Instance;

        static NuGetCredentialsValidator()
        {
            Instance = new NuGetCredentialsValidator();
        }

        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  Dictionary<string, string> groups)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 groups);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     Dictionary<string, string> options,
                                                     ref ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  options,
                                  ref resultLevelKind);
        }

        internal static List<string> ExtractHosts(string hostXmlAsString)
        {
            try
            {
                return ExtractHostsHelper(hostXmlAsString);
            }
            catch (XmlException)
            {
                // Maybe it's escaped? Try to unescape it...
                try
                {
                    string attemptTwoString = Regex.Unescape(hostXmlAsString).Replace(Environment.NewLine, string.Empty);

                    // Environment.NewLine is \r\n, and it will miss \n alone, so...
                    attemptTwoString = attemptTwoString.Replace("\n", string.Empty);
                    return ExtractHostsHelper(attemptTwoString);
                }
                catch
                {
                    // Still gotta return an empty list even if parsing failed
                    return new List<string>();
                }
            }
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(ref string matchedPattern,
                                                                             Dictionary<string, string> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("host", out string xmlHost) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            if (FilteringHelpers.LikelyPowershellVariable(secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            IEnumerable<string> hosts = ExtractHosts(xmlHost);
            var validationResults = new List<ValidationResult>();
            foreach (string host in hosts)
            {
                if (!Uri.IsWellFormedUriString(host, UriKind.Absolute))
                {
                    continue;
                }

                validationResults.Add(new ValidationResult
                {
                    Fingerprint = new Fingerprint
                    {
                        Id = id,
                        Host = host,
                        Secret = secret,
                        Platform = nameof(AssetPlatform.NuGet),
                    },
                    ValidationState = ValidationState.Unknown,
                });
            }

            return validationResults;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                Dictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string host = fingerprint.Host;
            string username = fingerprint.Id;
            string password = fingerprint.Secret;

            using HttpClient client = CreateHttpClient();

            try
            {
                using HttpResponseMessage responseWithNoCredentials = client
                    .GetAsync(host, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (responseWithNoCredentials.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        // Credentials not needed, this method of verification is indeterminate.
                        return ReturnUnknownAuthorization(ref message, host, account: username);
                    }

                    case HttpStatusCode.Unauthorized:
                    case HttpStatusCode.Forbidden:
                    {
                        // Credentials may resolve this, try again with them.
                        byte[] byteArray = Encoding.ASCII.GetBytes($"{username}:{password}");
                        client.DefaultRequestHeaders.Authorization =
                            new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));

                        using HttpResponseMessage responseWithCredentials = client
                            .GetAsync(host, HttpCompletionOption.ResponseHeadersRead)
                            .GetAwaiter()
                            .GetResult();

                        switch (responseWithCredentials.StatusCode)
                        {
                            case HttpStatusCode.OK:
                            {
                                // Credentials resolved the forbidden/unauthorized message we received.
                                return ReturnAuthorizedAccess(ref message, asset: host, account: username);
                            }

                            case HttpStatusCode.Forbidden:
                            case HttpStatusCode.Unauthorized:
                            {
                                return ReturnUnauthorizedAccess(ref message, asset: host, account: username);
                            }

                            default:
                            {
                                message = CreateUnexpectedResponseCodeMessage(responseWithCredentials.StatusCode);
                                return ValidationState.Unknown;
                            }
                        }
                    }

                    default:
                    {
                        message = CreateUnexpectedResponseCodeMessage(responseWithNoCredentials.StatusCode);
                        return ValidationState.Unknown;
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: host, account: username);
            }
        }

        private static List<string> ExtractHostsHelper(string hostXmlAsString)
        {
            var hostXml = new XmlDocument();
            hostXml.LoadXml(hostXmlAsString);

            // First attempt the most common format for package sources: <packageSources><add key="..." value="{the thing we're interested in}" /></packageSources>
            // <packageSources>...
            // <add ... >  <clear/> (the first node)
            // <add key="name of host" value="http://nugetfeedUrl.com" /> (we're looking for URL)
            var returnList = hostXml?.ChildNodes[0]?.ChildNodes
                                     .Cast<XmlNode>()
                                     .Where(x => x.Name.Equals("add", StringComparison.OrdinalIgnoreCase))
                                     .Select(x => x.Attributes["value"]?.Value ?? x.Attributes["Value"]?.Value)
                                     .ToList();

            if (returnList == null || returnList.Count == 0)
            {
                // Sometimes it looks like <packageSources>{the thing we're interested in}</packageSources>
                string host = hostXml?.ChildNodes[0]?.InnerText;
                returnList = new List<string>()
                {
                    host,
                };
            }

            return returnList ?? new List<string>();
        }
    }
}
