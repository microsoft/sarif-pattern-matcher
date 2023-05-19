// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    /// <summary>
    /// This class constructs signed requests to the Alibaba Cloud Elastic Compute Service
    /// which be used to determine whether exposed credentials are valid.
    /// See https://www.alibabacloud.com/help/en/elastic-compute-service/latest/request-signatures.
    /// </summary>
    internal class AlibabaEcsRequestSigner
    {
        private const string Method = "GET";

        private const string ISO8601BasicDateTimeFormat = "yyyy-MM-ddTHH:mm:ssZ";

        [ThreadStatic]
        private static StringBuilder queryString;

        private readonly DateTime timestamp;

        private readonly string signatureNonce;

        public AlibabaEcsRequestSigner(DateTime? dateTime = null, string signatureNonce = null)
        {
            this.timestamp = dateTime ?? DateTime.UtcNow;
            this.signatureNonce = signatureNonce ?? Guid.NewGuid().ToString();
        }

        public SortedDictionary<string, string> Parameters { get; set; }

        /// <summary>
        /// Sign the HTTP request using Alibaba Cloud access key and secret so it
        /// can be used to access Alibaba Cloud service REST API.
        /// </summary>
        /// <param name="request">httpRequest.</param>
        /// <param name="accessKey">Alibbaba Cloud access key.</param>
        /// <param name="secret">Alibaba Cloud secret.</param>
        public void SignRequest(HttpRequestMessage request, string accessKey, string secret)
        {
            const string format = "JSON";
            const string signatureVersion = "1.0";
            const string apiVersion = "2014-05-26";
            const string action = "DescribeRegions";
            const string signatureMethod = "HMAC-SHA1";
            const string url = "http://ecs.aliyuncs.com/";

            string timestamp = this.timestamp.ToString(ISO8601BasicDateTimeFormat);

            this.Parameters = new SortedDictionary<string, string>
            {
                { "AccessKeyId", accessKey },
                { "Action", action },
                { "Format", format },
                { "SignatureMethod", signatureMethod },
                { "SignatureNonce", this.signatureNonce },
                { "SignatureVersion", signatureVersion },
                { "Timestamp", timestamp },
                { "Version", apiVersion },
            };

            string stringToSign = this.ConstructStringToSign();
            string signature = Convert.ToBase64String(ComputeSignature(secret, stringToSign));

            this.Parameters.Add("Signature", PercentEncode(signature));

            string requestUri = $"{url}?{BuildQueryString(this.Parameters, encode: false)}";
            request.RequestUri = new Uri(requestUri);
        }

        private static byte[] ComputeSignature(string accessKeySecret, string stringToSign)
        {
            var hmac = new HMACSHA1(Encoding.UTF8.GetBytes($"{accessKeySecret}&"));
            byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));
            return hash;
        }

        private static string BuildQueryString(SortedDictionary<string, string> parameters, bool encode)
        {
            queryString ??= new StringBuilder();
            queryString.Clear();

            foreach (KeyValuePair<string, string> parameter in parameters)
            {
                queryString.AppendFormat("{0}={1}&",
                    encode ? PercentEncode(parameter.Key) : parameter.Key,
                    encode ? PercentEncode(parameter.Value) : parameter.Value);
            }

            return queryString.ToString().TrimEnd('&');
        }

        private static string PercentEncode(string value)
        {
            // Alibaba API requires the url encoded chars to be upper case.
            // E.g. "/" needs to be encoded to "%2F" not "%2f".
            // So need to use System.Net.WebUtility.UrlEncode not System.Web.HttpUtility.UrlEncode.
            return System.Net.WebUtility.UrlEncode(value)
                .Replace("+", "%20")
                .Replace("*", "%2A")
                .Replace("%7E", "~");
        }

        private string ConstructStringToSign()
        {
            return $"{Method}&{PercentEncode("/")}&{PercentEncode(BuildQueryString(this.Parameters, encode: true))}";
        }
    }
}
