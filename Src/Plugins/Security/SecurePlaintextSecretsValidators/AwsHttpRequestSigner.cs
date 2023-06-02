// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    // https://docs.aws.amazon.com/general/latest/gr/create-signed-request.html

    internal class AwsHttpRequestSigner : IDisposable
    {
        private const string ISO8601BasicDateTimeFormat = "yyyyMMddTHHmmssZ";

        private readonly SHA256 sha256;
        private readonly string accessKey;
        private readonly string accessSecret;

        public AwsHttpRequestSigner(string accessKey, string accessSecret)
        {
            this.accessKey = accessKey;
            this.accessSecret = accessSecret;
            this.sha256 = SHA256.Create();
        }

        public virtual string Version => "AWS4";

        public virtual string RequestType => "aws4_request";

        public virtual string Algorithm => "AWS4-HMAC-SHA256";

        public virtual string HostHeaderName => "host";

        public virtual string DateHeaderName => "x-amz-date";

        public virtual string ContentSha256HeaderName => "x-amz-content-sha256";

        public void SignRequest(HttpRequestMessage request,
                                string region,
                                string service,
                                DateTime? dateTime = null)
        {
            this.CleanHeaders(request.Headers);

            string host = request.RequestUri.Host;
            byte[] content = request.Content?.ReadAsByteArrayAsync().GetAwaiter().GetResult() ?? Array.Empty<byte>();
            string contentHash = GetHash(content);

            DateTime date = dateTime ?? DateTime.UtcNow;
            string requestDateString = date.ToString(ISO8601BasicDateTimeFormat);
            string dateStamp = date.ToString("yyyyMMdd");

            string credentialScope = $"{dateStamp}/{region}/{service}/{this.RequestType}";
            string signedHeaderNames = $"{this.HostHeaderName};{this.ContentSha256HeaderName};{this.DateHeaderName}";

            string canonicalRequest = this.ConstructCanonicalRequest(request.Method.ToString(), signedHeaderNames, host, contentHash, requestDateString);

            string stringToSign = this.ConstructStringToSign(credentialScope, canonicalRequest, requestDateString);

            byte[] signingKey = this.GetSignatureKey(this.accessSecret, dateStamp, region, service, this.RequestType);

            string signature = ToHexString(HmacSha256Hash(signingKey, stringToSign));

            string authorizationHeader = $"{this.Algorithm} Credential={this.accessKey}/{credentialScope}, SignedHeaders={signedHeaderNames}, Signature={signature}";

            request.Headers.Merge(new Dictionary<string, string>
            {
                { this.HostHeaderName, host },
                { this.ContentSha256HeaderName, contentHash },
                { this.DateHeaderName, requestDateString },
            });
            request.Headers.TryAddWithoutValidation("Authorization", authorizationHeader);
        }

        public void Dispose()
        {
            sha256?.Dispose();
        }

        private static byte[] HmacSha256Hash(byte[] key, string msg)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(Encoding.UTF8.GetBytes(msg));
            }
        }

        private static string ToHexString(IReadOnlyCollection<byte> array)
        {
            var hex = new StringBuilder(array.Count * 2);
            foreach (byte b in array)
            {
                hex.AppendFormat("{0:x2}", b);
            }

            return hex.ToString();
        }

        private string ConstructCanonicalRequest(string httpMethod, string signedHeaderNames, string host, string contentSha256, string dateString)
        {
            string canonicalUri = "/";
            string canonicalQuerystring = string.Empty;
            string canonicalHeaders = $"{this.HostHeaderName}:{host}\n{this.ContentSha256HeaderName}:{contentSha256}\n{this.DateHeaderName}:{dateString}";
            return $"{httpMethod}\n{canonicalUri}\n{canonicalQuerystring}\n{canonicalHeaders}\n\n{signedHeaderNames}\n{contentSha256}";
        }

        private string ConstructStringToSign(string credentialScope, string canonicalRequest, string dateString)
        {
            string stringToSign = $"{this.Algorithm}\n{dateString}\n{credentialScope}\n";
            stringToSign += GetHash(Encoding.UTF8.GetBytes(canonicalRequest));
            return stringToSign;
        }

        private void CleanHeaders(HttpRequestHeaders headers)
        {
            headers.Remove(this.HostHeaderName);
            headers.Remove(this.ContentSha256HeaderName);
            headers.Remove(this.DateHeaderName);
            headers.Remove("Authorization");
        }

        private byte[] GetSignatureKey(string key, string date_stamp, string regionName, string serviceName, string requestType)
        {
            byte[] key_date = HmacSha256Hash(Encoding.UTF8.GetBytes(this.Version + key), date_stamp);
            byte[] key_region = HmacSha256Hash(key_date, regionName);
            byte[] key_service = HmacSha256Hash(key_region, serviceName);
            return HmacSha256Hash(key_service, requestType);
        }

        private string GetHash(byte[] bytes)
        {
            byte[] result = this.sha256.ComputeHash(bytes);
            return ToHexString(result);
        }
    }
}
