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

        // We can't count on the int values of the enumerations being ordered as we want,
        // so order them manually
        private readonly Dictionary<ValidationState, int> badResponseSorting = new Dictionary<ValidationState, int>()
        {
            { ValidationState.Unknown, 0 },
            { ValidationState.UnknownHost, 1 },
            { ValidationState.Unauthorized, 2 },
        };

        static NuGetCredentialsValidator()
        {
            Instance = new NuGetCredentialsValidator();
        }

        public static ValidationState IsValidStatic(ref string matchedPattern,
                                                    ref Dictionary<string, string> groups,
                                                    ref string failureLevel,
                                                    ref string message,
                                                    out Fingerprint fingerprint)
        {
            return ValidatorBase.IsValidStatic(Instance,
                                               ref matchedPattern,
                                               ref groups,
                                               ref failureLevel,
                                               ref message,
                                               out fingerprint);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint, ref string message, ref Dictionary<string, string> options)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options);
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

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                               ref Dictionary<string, string> groups,
                                                               ref string failureLevel,
                                                               ref string message,
                                                               out Fingerprint fingerprint)
        {
            fingerprint = default;

            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("host", out string host) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationState.NoMatch;
            }

            if (FilteringHelpers.LikelyPowershellVariable(secret))
            {
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint
            {
                Id = id,
                Host = host, // technically, this is XML which could contain multiple hosts.
                Secret = secret,
                Platform = nameof(AssetPlatform.NuGet),
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options)
        {
            string hostXmlAsString = fingerprint.Host;
            string username = fingerprint.Id;
            string password = fingerprint.Secret;

            IEnumerable<string> hosts = ExtractHosts(hostXmlAsString);

            // Usually there will only be a single host.
            // In any case, attempt to pass the credentials to each host one by one.
            using HttpClient client = CreateHttpClient();
            int highestResponse = 0;
            foreach (string host in hosts)
            {
                if (!Uri.IsWellFormedUriString(host, UriKind.Absolute))
                {
                    continue;
                }

                using (HttpResponseMessage responseWithNoCredentials = client
                .GetAsync(host, HttpCompletionOption.ResponseHeadersRead)
                .GetAwaiter()
                .GetResult())
                {
                    switch (responseWithNoCredentials.StatusCode)
                    {
                        case HttpStatusCode.OK:
                            // Credentials not needed, this method of verification is indeterminate.
                            highestResponse = AssignHighestResponse(highestResponse, ValidationState.Unknown);
                            break;
                        case HttpStatusCode.Unauthorized:
                        case HttpStatusCode.Forbidden:
                            // Credentials may resolve this, try again with them.
                            byte[] byteArray = Encoding.ASCII.GetBytes($"{username}:{password}");
                            client.DefaultRequestHeaders.Authorization =
                                new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));

                            using (HttpResponseMessage responseWithCredentials = client
                            .GetAsync(host, HttpCompletionOption.ResponseHeadersRead)
                            .GetAwaiter()
                            .GetResult())
                            {
                                switch (responseWithCredentials.StatusCode)
                                {
                                    case HttpStatusCode.OK:
                                        // Credentials resolved the forbidden/unauthorized message we received.
                                        return ReturnAuthorizedAccess(ref message, username);
                                    case HttpStatusCode.Forbidden:
                                    case HttpStatusCode.Unauthorized:
                                        // Credentials didn't fix the error, but it may be that we're missing
                                        // something in the request.
                                        highestResponse = AssignHighestResponse(highestResponse, ValidationState.Unauthorized);
                                        break;
                                    default:
                                        highestResponse = AssignHighestResponse(highestResponse, ValidationState.Unknown);
                                        break;
                                }
                            }

                            break;
                        default:
                            highestResponse = AssignHighestResponse(highestResponse, ValidationState.Unknown);
                            break;
                    }
                }
            }

            switch (highestResponse)
            {
                case 0:
                    return ReturnUnknownAuthorization(ref message, username);
                case 1:
                    return ReturnUnknownHost(ref message, username);
                case 2:
                    return ReturnUnauthorizedAccess(ref message, username);
                default:
                    return ReturnUnknownAuthorization(ref message, username);
            }
        }



        private static List<string> ExtractHostsHelper(string hostXmlAsString)
        {
            var hostXml = new XmlDocument();
            hostXml.LoadXml(hostXmlAsString);

            // First attempt the most common format for package sources: <packageSources><add key="..." value="{the thing we're interested in}" /></packageSources>
            var returnList = hostXml?.ChildNodes[0] // <packageSources>...
                            ?.ChildNodes.Cast<XmlNode>().Where(x => x.Name.Equals("add", StringComparison.OrdinalIgnoreCase)) // <add ... >  <clear/> (the first node)
                                .Select(x => x.Attributes["value"]?.Value ?? x.Attributes["Value"]?.Value).ToList(); // <add key="name of host" value="http://nugetfeedUrl.com" /> (we're looking for URL)

            if (returnList == null || returnList.Count() == 0)
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

        private int AssignHighestResponse(int highestResponseSoFar, ValidationState response)
        {
            return Math.Max(highestResponseSoFar, badResponseSorting[response]);
        }
    }
}
