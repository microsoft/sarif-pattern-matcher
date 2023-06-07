// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    // https://docs.aws.amazon.com/general/latest/gr/create-signed-request.html

    public class AwsHttpRequestSigner : IDisposable
    {
        private const string ISO8601BasicDateTimeFormat = "yyyyMMddTHHmmssZ";

        [ThreadStatic]
        private static StringBuilder s_hex;

        private readonly SHA256 sha256;
        private readonly string accessKey;
        private readonly string secretKey;

        public AwsHttpRequestSigner(string accessKey, string secretKey)
        {
            this.accessKey = accessKey ?? throw new ArgumentNullException(nameof(accessKey));

            this.secretKey = secretKey ?? throw new ArgumentNullException(nameof(secretKey));

            this.sha256 = SHA256.Create();
        }

        public virtual string Version => "AWS4";

        public virtual string RequestType => "aws4_request";

        public virtual string Algorithm => "AWS4-HMAC-SHA256";

        public virtual string HostHeaderName => "host";

        public virtual string DateHeaderName => "x-amz-date";

        public virtual string ContentSha256HeaderName => "x-amz-content-sha256";

        public void SignRequest(HttpRequestMessage request, string region, string service, DateTime? dateTime = null)
        {
            if (request == null) { throw new ArgumentNullException(nameof(request)); }

            if (region == null) { throw new ArgumentNullException(nameof(region)); }

            if (service == null) { throw new ArgumentNullException(nameof(service)); }

            string host = request.RequestUri.Host;

            byte[] content = request.Content?.ReadAsByteArrayAsync().Result ?? Array.Empty<byte>();

            string contentHash = this.GetHash(content);

            DateTime date = dateTime ?? DateTime.UtcNow;

            string dateStamp = date.ToString("yyyyMMdd");

            string requestDateString = date.ToString(ISO8601BasicDateTimeFormat);

            string credentialScope = $"{dateStamp}/{region}/{service}/{this.RequestType}";

            request.Headers.Merge(new Dictionary<string, string>
            {
                { this.HostHeaderName, host },
                { this.ContentSha256HeaderName, contentHash },
                { this.DateHeaderName, requestDateString },
            });

            string canonicalRequest = this.ConstructCanonicalRequest(
                request,
                contentHash,
                out string signedHeaders);

            string stringToSign = this.ConstructStringToSign(
                credentialScope,
                canonicalRequest,
                requestDateString);

            string signature = this.GetSignature(
                this.secretKey,
                dateStamp,
                region,
                service,
                this.RequestType,
                stringToSign);

            string authorizationHeader = string.Format("{0} Credential={1}/{2}, SignedHeaders={3}, Signature={4}",
                this.Algorithm,
                this.accessKey,
                credentialScope,
                signedHeaders,
                signature);

            request.Headers.TryAddWithoutValidation("Authorization", authorizationHeader);
        }

        public void Dispose()
        {
            this.sha256?.Dispose();
        }

        private string ConstructCanonicalRequest(HttpRequestMessage request, string hashPayload, out string signedHeaders)
        {
            string httpMethod = request.Method.ToString();

            string canonicalUri = "/";

            string canonicalQuerystring = string.Empty;

            var headerKeyList = new List<string>();

            var headerKeyValuePairList = new List<string>();

            foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers.OrderBy(a => a.Key, StringComparer.OrdinalIgnoreCase))
            {
                headerKeyList.Add(header.Key.ToLower());

                headerKeyValuePairList.Add($"{header.Key.ToLower()}:{string.Join(",", header.Value.Select(s => s.Trim()))}");
            }

            signedHeaders = string.Join(";", headerKeyList);

            string canonicalHeaders = string.Join("\n", headerKeyValuePairList) + "\n";

            return string.Format("{0}\n{1}\n{2}\n{3}\n{4}\n{5}",
                                  httpMethod,
                                  canonicalUri,
                                  canonicalQuerystring,
                                  canonicalHeaders,
                                  signedHeaders,
                                  hashPayload);
        }

        private string ConstructStringToSign(string credentialScope, string canonicalRequest, string dateString)
        {
            return string.Format("{0}\n{1}\n{2}\n{3}",
                this.Algorithm,
                dateString,
                credentialScope,
                this.GetHash(Encoding.UTF8.GetBytes(canonicalRequest)));
        }

        private string GetSignature(string key, string dateStamp, string regionName, string serviceName, string requestType, string stringToSign)
        {
            byte[] keyBytes = this.HmacSha256Hash(Encoding.UTF8.GetBytes(this.Version + key), dateStamp);

            keyBytes = this.HmacSha256Hash(keyBytes, regionName);

            keyBytes = this.HmacSha256Hash(keyBytes, serviceName);

            keyBytes = this.HmacSha256Hash(keyBytes, requestType);

            keyBytes = this.HmacSha256Hash(keyBytes, stringToSign);

            return this.ToHexString(keyBytes);
        }

        private string GetHash(byte[] bytes)
        {
            byte[] result = this.sha256.ComputeHash(bytes);

            return this.ToHexString(result);
        }

        private byte[] HmacSha256Hash(byte[] key, string message)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
            }
        }

        private string ToHexString(IReadOnlyCollection<byte> array)
        {
            s_hex ??= new StringBuilder();

            s_hex.Clear();

            s_hex.Capacity = array.Count * 2;

            foreach (byte b in array)
            {
                s_hex.AppendFormat("{0:x2}", b);
            }

            return s_hex.ToString();
        }
    }
}
