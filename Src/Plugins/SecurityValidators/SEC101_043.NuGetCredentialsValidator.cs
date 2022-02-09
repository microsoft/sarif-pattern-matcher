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

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators
{
    public class NuGetCredentialsValidator : DynamicValidatorBase
    {
        internal const string RandomGuid = "05C89BF5-9DF2-4F8C-8F93-FF3EF66E643D";

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

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("host", out FlexMatch hostsXml) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            IEnumerable<string> hosts = ExtractHosts(hostsXml.Value);
            List<(string user, string password)> credentials = ExtractCredentials(secret.Value);
            var validationResults = new List<ValidationResult>();
            foreach (string host in hosts)
            {
                if (!Uri.IsWellFormedUriString(host, UriKind.Absolute))
                {
                    continue;
                }

                foreach ((string user, string password) in credentials)
                {
                    validationResults.Add(new ValidationResult
                    {
                        Fingerprint = new Fingerprint
                        {
                            Id = user,
                            Host = host,
                            Secret = password,
                            Platform = nameof(AssetPlatform.NuGet),
                        },
                        ValidationState = ValidationState.Unknown,
                    });
                }
            }

            return validationResults;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string id = fingerprint.Id;
            string host = fingerprint.Host;
            string secret = fingerprint.Secret;

            HttpClient client = CreateOrRetrieveCachedHttpClient();

            try
            {
                ValidationState validationState = ValidateWithEmptyAndRandomKey(host,
                                                                                id);

                if (validationState == ValidationState.NoMatch)
                {
                    return validationState;
                }

                // Credentials may resolve this, try again with them.
                byte[] byteArray = Encoding.ASCII.GetBytes($"{id}:{secret}");

                using var request = new HttpRequestMessage(HttpMethod.Get, host);
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));

                using HttpResponseMessage responseWithCredentials = client
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (responseWithCredentials.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        // Credentials resolved the forbidden/unauthorized message we received.
                        return ReturnAuthorizedAccess(ref message, asset: host, account: id);
                    }

                    case HttpStatusCode.Forbidden:
                    case HttpStatusCode.Unauthorized:
                    {
                        return ReturnUnauthorizedAccess(ref message, asset: host, account: id);
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, responseWithCredentials.StatusCode, asset: host, account: id);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset: host, account: id);
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

        private static List<(string user, string password)> ExtractCredentials(string credentialXmlAsString)
        {
            var list = new List<(string user, string password)>();
            var credentialsXml = new XmlDocument();

            try
            {
                credentialsXml.LoadXml(credentialXmlAsString);
            }
            catch (XmlException)
            {
                return list;
            }

            IEnumerable<XmlNode> credentials = credentialsXml?.ChildNodes[0]?.ChildNodes.Cast<XmlNode>();
            foreach (XmlNode credential in credentials)
            {
                string user = null;
                string password = null;
                foreach (XmlNode item in credential.ChildNodes.Cast<XmlNode>())
                {
                    if (item.Attributes == null)
                    {
                        continue;
                    }

                    IEnumerable<XmlNode> current = item.Attributes.Cast<XmlNode>();
                    if (current.Any(a => a.Value.Equals("username", StringComparison.OrdinalIgnoreCase)))
                    {
                        user = current.FirstOrDefault(a => a.Name.Equals("value", StringComparison.OrdinalIgnoreCase))?.Value;
                    }

                    if (current.Any(a => a.Value.Equals("password", StringComparison.OrdinalIgnoreCase) ||
                                         a.Value.Equals("cleartextpassword", StringComparison.OrdinalIgnoreCase)))
                    {
                        password = current.FirstOrDefault(a => a.Name.Equals("value", StringComparison.OrdinalIgnoreCase))?.Value;
                    }
                }

                if (!string.IsNullOrEmpty(user) && !string.IsNullOrEmpty(password))
                {
                    list.Add((user, password));
                }
            }

            return list;
        }

        private ValidationState ValidateWithEmptyAndRandomKey(string uri,
                                                              string id)
        {
            HttpClient httpClient = CreateOrRetrieveCachedHttpClient();

            // Making a request without a key.
            using HttpResponseMessage responseWithoutSecret = httpClient
                .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead)
                .GetAwaiter()
                .GetResult();

            if (responseWithoutSecret.StatusCode == HttpStatusCode.OK ||
                responseWithoutSecret.StatusCode == HttpStatusCode.NotFound ||
                responseWithoutSecret.StatusCode == HttpStatusCode.NonAuthoritativeInformation)
            {
                return ValidationState.NoMatch;
            }

            // Making a request with a random generated guid.
            byte[] byteArray = Encoding.ASCII.GetBytes($"{id}:{RandomGuid}");

            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));

            using HttpResponseMessage responseDummy = httpClient
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                .GetAwaiter()
                .GetResult();

            if (responseDummy.StatusCode == HttpStatusCode.OK ||
                responseDummy.StatusCode == HttpStatusCode.NotFound ||
                responseDummy.StatusCode == HttpStatusCode.NonAuthoritativeInformation)
            {
                return ValidationState.NoMatch;
            }

            return ValidationState.Unknown;
        }
    }
}
