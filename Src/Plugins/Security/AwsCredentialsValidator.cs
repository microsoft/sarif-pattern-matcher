// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;
using Amazon.IdentityManagement.Model.Internal.MarshallTransformations;
using Amazon.Runtime;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    internal class AwsCredentialsValidator : ValidatorBase
    {
        internal static AwsCredentialsValidator Instance = new AwsCredentialsValidator();

        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return ValidatorBase.IsValidStatic(Instance,
                                               ref matchedPattern,
                                               ref groups,
                                               ref failureLevel,
                                               ref fingerprint,
                                               ref message);
        }

        public static string IsValidDynamic(ref string fingerprint, ref string message)
        {
            return ValidatorBase.IsValidDynamic(Instance,
                                                ref fingerprint,
                                                ref message);
        }

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            string id = groups["id"];
            string key = groups["key"];

            fingerprintText = new Fingerprint
            {
                Id = id,
                Key = key,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            var fingerprint = new Fingerprint(fingerprintText);

            string id = fingerprint.Id;
            string key = fingerprint.Key;

            try
            {
                var iamClient = new AmazonIdentityManagementServiceClient(id, key);

                GetAccountAuthorizationDetailsRequest request;
                GetAccountAuthorizationDetailsResponse response;

                GetUserRequest userRequest = new GetUserRequest();
                GetUserResponse userResponse = iamClient.GetUserAsync().GetAwaiter().GetResult();

                request = new GetAccountAuthorizationDetailsRequest();
                response = iamClient.GetAccountAuthorizationDetailsAsync(request).GetAwaiter().GetResult();

                message = BuildAuthorizedMessage(id, response);
            }
            catch (AmazonIdentityManagementServiceException e)
            {
                switch (e.ErrorCode)
                {
                    case "InvalidClientTokenId":
                    case "SignatureDoesNotMatch":
                    {
                        return nameof(ValidationState.NoMatch);
                    }
                }

                message = $"An unexpected exception was caught attempting to authenticate AWS id '{id}': {e.Message}";
                return nameof(ValidationState.Unknown);
            }
            catch (Exception e)
            {
                message = $"An unexpected exception was caught attempting to authentic AWS id '{id}': {e.Message}";
                return nameof(ValidationState.Unknown);
            }

            /*          var client = new HttpClient();

                        try
                        {
                            string uri = "https://iam.amazonaws.com/?Action=GetAccountAuthorizationDetails" +
                                         "?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
                                        $"&X-Amz-Credential={id}";

                            HttpResponseMessage response = client.GetAsync(uri).GetAwaiter().GetResult();

                            switch (response.StatusCode)
                            {
                                case HttpStatusCode.Forbidden:
                                {
                                    message = $"for AWS credential id '{id}'.";
                                    return nameof(ValidationState.Unauthorized);
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            message = $"An unexpected exception was caught attempting to authentic AWS id '{id}': {e.Message}";
                            return nameof(ValidationState.Unknown);
                        }
            */
            return nameof(ValidationState.Authorized);
        }

        private string BuildAuthorizedMessage(string id, GetAccountAuthorizationDetailsResponse response)
        {
            var policyNames = new List<string>();

            foreach (ManagedPolicyDetail policy in response.Policies)
            {
                policyNames.Add(policy.PolicyName);
            }

            string policyNamesText = string.Join(", ", policyNames);
            return $"id '{id}' is authorized for role policies '{policyNamesText}'.";
        }
    }
}
