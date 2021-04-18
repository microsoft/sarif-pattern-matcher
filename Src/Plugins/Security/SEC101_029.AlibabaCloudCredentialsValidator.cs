// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using Aliyun.Acs.Core;
using Aliyun.Acs.Core.Exceptions;
using Aliyun.Acs.Core.Profile;

using Aliyun.Acs.Iot.Model.V20170420;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class AlibabaCloudCredentialsValidator : ValidatorBase
    {
        internal static AlibabaCloudCredentialsValidator Instance;

        private const string KeyNotFound = "InvalidAccessKeyId.NotFound";
        private const string InvalidSecret = "SDK.InvalidAccessKeySecret";
        private const string ProductKeyInvalidFormat = "The productKey format is incorrect.";

        static AlibabaCloudCredentialsValidator()
        {
            Instance = new AlibabaCloudCredentialsValidator();
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

        // TODO: uncomment when Alibaba release a signed package/dll.
        // public static ValidationState IsValidDynamic(ref Fingerprint fingerprint, ref string message, ref Dictionary<string, string> options)
        // {
        //     return IsValidDynamic(Instance,
        //                           ref fingerprint,
        //                           ref message,
        //                           ref options);
        // }

        protected override ValidationState IsValidStaticHelper(ref string matchedPattern,
                                                               ref Dictionary<string, string> groups,
                                                               ref string message,
                                                               out ResultLevelKind resultLevelKind,
                                                               out Fingerprint fingerprint)
        {
            fingerprint = default;
            resultLevelKind = default;

            if (!groups.TryGetNonEmptyValue("id", out string id) ||
                !groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationState.NoMatch;
            }

            fingerprint = new Fingerprint()
            {
                Id = id,
                Secret = secret,
                Platform = nameof(AssetPlatform.AlibabaCloud),
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options)
        {
            string account = fingerprint.Id;
            string password = fingerprint.Secret;

            try
            {
                // Taken from https://www.alibabacloud.com/help/doc-detail/63638.htm
                IClientProfile clientProfile = DefaultProfile.GetProfile("cn-shanghai", account, password);
                var client = new DefaultAcsClient(clientProfile);

                var request = new PubRequest();

                // We don't actually care about any of the product stuff, so just leave dummy values in.
                request.ProductKey = "<productKey>";
                request.TopicFullName = "/<productKey>/<deviceName>/get";
                byte[] payload = Encoding.Default.GetBytes("Invalid payload.");
                string payloadStr = Convert.ToBase64String(payload);
                request.MessageContent = payloadStr;
                request.Qos = 0;
                PubResponse response = client.GetAcsResponse(request);

                if (!response.ErrorMessage.Equals(ProductKeyInvalidFormat))
                {
                    message = $"Unexpected response from Alibaba Cloud: '{response.ErrorMessage}'";
                    return ValidationState.Unknown;
                }
            }
            catch (ClientException ce)
            {
                switch (ce.ErrorCode)
                {
                    case KeyNotFound:
                        // Not even the client id we found is valid. Return no match.
                        return ValidationState.NoMatch;

                    case InvalidSecret:
                        // The client ID is valid but the secret was not.
                        return ReturnUnauthorizedAccess(ref message, asset: account);

                    default:
                        return ReturnUnhandledException(ref message, ce, asset: account);
                }
            }

            // If all goes well, we'll receive a "product format invalid" message in the response
            // which means authentication succeeded. Therefore the id and secret are valid.
            return ReturnAuthorizedAccess(ref message, asset: account);
        }
    }
}
