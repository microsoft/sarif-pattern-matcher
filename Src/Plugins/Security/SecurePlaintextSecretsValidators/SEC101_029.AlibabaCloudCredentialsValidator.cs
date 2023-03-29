// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class AlibabaCloudCredentialsValidator : DynamicValidatorBase
    {
        internal static string UriTemplate = "https://ecs.aliyuncs.com/";

        internal DateTime? Timestamp { get; set; }

        internal string SignatureNonce { get; set; }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            if (IsFalsePositiveOrBelongsToOtherSecurityModel(secret.Value))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Id = id.Value,
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.AlibabaCloud),
                },
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                        ref string message,
                                                        IDictionary<string, string> options,
                                                        ref ResultLevelKind resultLevelKind)
        {
            // https://www.alibabacloud.com/help/en/log-service/latest/accesskey-pair
            // https://www.alibabacloud.com/help/en/log-service/latest/request-signatures#t13222.html
            // https://next.api.alibabacloud.com/product/Ecs#endpoint

            string id = fingerprint.Id;
            string secret = fingerprint.Secret;
            string asset = secret.Truncate();

            try
            {
                HttpClient client = CreateOrRetrieveCachedHttpClient();

                using var request = new HttpRequestMessage(HttpMethod.Get, UriTemplate);

                var requestSigner = new AlibabaEcsRequestSigner(this.Timestamp, this.SignatureNonce);

                requestSigner.SignRequest(request, id, secret);

                using HttpResponseMessage response = client.ReadResponseHeaders(request);

                if (response.IsSuccessStatusCode)
                {
                    return ValidationState.Authorized;
                }

                switch (response.StatusCode)
                {
                    case HttpStatusCode.Forbidden:
                    {
                        // "Forbidden.AccessKeyDisabled"
                        return ValidationState.Unauthorized;
                    }

                    case HttpStatusCode.NotFound:
                    {
                        // "InvalidAccessKeyId.NotFound"
                        return ValidationState.Unauthorized;
                    }

                    case HttpStatusCode.BadRequest:
                    {
                        // "IncompleteSignature"
                        return ValidationState.Unauthorized;
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, asset);
            }
        }
    }
}
