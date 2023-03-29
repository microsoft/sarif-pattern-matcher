// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class AkamaiCredentialsValidator : DynamicValidatorBase
    {
        internal static HttpRequestMessage GenerateRequestMessage(string id,
                                                                  string host,
                                                                  string secret,
                                                                  string resource,
                                                                  string scanIdentityGuid,
                                                                  DateTime datetime)
        {
            string timestamp = datetime.ToString("yyyyMMdd'T'HH:mm:ss+0000");
            var request = new HttpRequestMessage(HttpMethod.Get, $"{host}/ccu/v2/queues/default");
            string requestData = GetRequestData(request.Method.ToString(), request.RequestUri);
            string authData = GetAuthDataValue(id, resource, timestamp, scanIdentityGuid);
            string authHeader = GetAuthorizationHeaderValue(secret, timestamp, authData, requestData);
            request.Headers.Add("Authorization", authHeader);

            return request;
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch id = groups["id"];
            FlexMatch host = groups["host"];
            FlexMatch secret = groups["secret"];
            FlexMatch resource = groups["resource"];

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Id = id.Value,
                    Host = host.Value,
                    Secret = secret.Value,
                    Resource = resource.Value,
                },
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string id = fingerprint.Id;
            string host = fingerprint.Host;
            string secret = fingerprint.Secret;
            string asset = secret.Truncate();
            string resource = fingerprint.Resource;

            string date;
            string scanIdentityGuid;
            DateTime datetime = DateTime.UtcNow;

            if (options.TryGetValue("datetime", out date))
            {
                DateTime.TryParse(date, out datetime);
            }

            if (!options.TryGetValue("scanIdentityGuid", out scanIdentityGuid))
            {
                scanIdentityGuid = ScanIdentityGuid;
            }

            try
            {
                HttpClient httpClient = CreateOrRetrieveCachedHttpClient();

                using HttpRequestMessage request = GenerateRequestMessage(id, host, secret, resource, scanIdentityGuid, datetime);

                using HttpResponseMessage httpResponse = httpClient
                    .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (httpResponse.StatusCode)
                {
                    case System.Net.HttpStatusCode.OK:
                    {
                        return ValidationState.Authorized;
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, httpResponse.StatusCode);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset);
            }
        }

        private static string GetRequestData(string method, Uri uri)
        {
            string headers = string.Empty;
            string bodyHash = string.Empty;

            return string.Format("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t",
                method.ToUpper(),
                uri.Scheme,
                uri.Host,
                uri.PathAndQuery,
                headers,
                bodyHash);
        }

        private static string GetAuthDataValue(string id,
                                               string resource,
                                               string timestamp,
                                               string scanIdentityGuid)
        {
            return string.Format("{0} client_token={1};access_token={2};timestamp={3};nonce={4};",
                "EG1-HMAC-SHA256",
                id,
                resource,
                timestamp,
                scanIdentityGuid.ToLower());
        }

        private static string GetAuthorizationHeaderValue(string secret,
                                                          string timestamp,
                                                          string authData,
                                                          string requestData)
        {
            string hashType = "HMACSHA256";

            byte[] time = Encoding.UTF8.GetBytes(timestamp);
            string signingKey = Convert.ToBase64String(ComputeKeyedHash(time, secret, hashType));

            byte[] data = Encoding.UTF8.GetBytes(string.Format("{0}{1}", requestData, authData));
            string authSignature = Convert.ToBase64String(ComputeKeyedHash(data, signingKey, hashType));

            return string.Format("{0}signature={1}", authData, authSignature);
        }

        private static byte[] ComputeKeyedHash(byte[] data, string key, string hashType)
        {
            using (var algorithm = HMAC.Create(hashType.ToString()))
            {
                algorithm.Key = Encoding.UTF8.GetBytes(key);
                return algorithm.ComputeHash(data);
            }
        }
    }
}
