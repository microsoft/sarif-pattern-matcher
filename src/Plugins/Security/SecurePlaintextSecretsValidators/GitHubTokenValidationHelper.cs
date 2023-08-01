// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Newtonsoft.Json.Linq;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    internal class GitHubTokenValidationHelper
    {
        protected virtual string[] GitHubEndpoints => new[]
        {
            "https://api.github.com/user",
        };

        internal ValidationState ValidateToken(
            HttpClient client,
            ref Fingerprint fingerprint,
            ref string message)
        {
            ValidationState validationState = ValidationState.Unknown;

            foreach (string uri in this.GitHubEndpoints)
            {
                validationState = ValidateTokenForEndpoint(client, uri, ref fingerprint, ref message);
                if (validationState == ValidationState.Authorized)
                {
                    return validationState;
                }
            }

            return validationState;
        }

        private static ValidationState ValidateTokenForEndpoint(
            HttpClient client,
            string uri,
            ref Fingerprint fingerprint,
            ref string message)
        {
            string secret = fingerprint.Secret;
            string asset = secret.Truncate();

            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);

                using HttpResponseMessage response = client.ReadResponseHeaders(request);

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        string responseJson = response.Content.ReadAsStringAsync().Result;

                        RetrieveUserMetadata(responseJson,
                                             out string login,
                                             out string id,
                                             out string name);

                        fingerprint.Id = login;
                        string username = string.IsNullOrEmpty(name) ? name : $" ({name})";
                        asset = $"{login}{username}";
                        message = BuildMessage(login, id, username);

                        GetUserOrganizations(client, uri, secret, ref fingerprint, ref message);

                        return ValidationState.Authorized;
                    }

                    case HttpStatusCode.Forbidden:
                    {
                        // rate limit exceeded or not permission to access user API
                        return ValidationState.Authorized;
                    }

                    case HttpStatusCode.Unauthorized:
                    {
                        message = "The provided secret is not authorized to access github.com";
                        return ValidationState.Unauthorized;
                    }

                    default:
                    {
                        return ValidatorBase.ReturnUnexpectedResponseCode(ref message, response.StatusCode);
                    }
                }
            }
            catch (Exception e)
            {
                return ValidatorBase.ReturnUnhandledException(ref message, e, asset);
            }
        }

        private static string BuildMessage(string login, string id, string name)
        {
            return $"the compromised GitHub account is '[{login}{name}](https://github.com/{id})'";
        }

        private static void RetrieveUserMetadata(string responseJson, out string login, out string id, out string name)
        {
            var responseObject = JObject.Parse(responseJson);

            login = (string)responseObject["login"];
            id = (string)responseObject["id"];
            name = (string)responseObject["name"];
        }

        private static void GetUserOrganizations(HttpClient client, string endpointUrl, string secret, ref Fingerprint fingerprint, ref string message)
        {
            try
            {
                string uri = $"{endpointUrl}/orgs";
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", secret);

                using HttpResponseMessage response = client.ReadResponseHeaders(request);

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        string responseJson = response.Content.ReadAsStringAsync().Result;
                        var orgsArray = JArray.Parse(responseJson);

                        string orgNames = string.Empty;
                        if (orgsArray.Count == 0)
                        {
                            orgNames = "[None]";
                        }
                        else
                        {
                            orgNames = string.Join(", ", orgsArray.Select(org => org["login"]));
                            fingerprint.Resource = orgNames;
                        }

                        message += $" which has access to the following orgs '{orgNames}'";
                        return;
                    }

                    case HttpStatusCode.Forbidden:
                    case HttpStatusCode.Unauthorized:
                    {
                        // The token is valid but doesn't have sufficient scope to retrieve org data.
                        message += ". This token has insufficient permissions to retrieve organization data";
                        return;
                    }
                }
            }
            catch
            {
                // not raise the error of getting org data
                return;
            }
        }
    }
}
