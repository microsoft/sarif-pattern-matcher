// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class AwsCredentialsValidator : ValidatorBase
    {
        internal static IRegex RegexEngine;
        internal static AwsCredentialsValidator Instance;

        private const string UserPrefix = "User: ";
        private const string UserSuffix = " is not authorized";
        private static readonly string AwsUserExpression = $"^{UserPrefix}.+?{UserSuffix}";

        static AwsCredentialsValidator()
        {
            RegexEngine = RE2Regex.Instance;
            Instance = new AwsCredentialsValidator();

            RegexEngine.IsMatch(string.Empty, AwsUserExpression);
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

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     ref Dictionary<string, string> options,
                                                     out ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options,
                                  out resultLevelKind);
        }

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

            fingerprint = new Fingerprint
            {
                Id = id,
                Secret = secret,
                Platform = nameof(AssetPlatform.Aws),
            };

            return ValidationState.Unknown;
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options,
                                                                out ResultLevelKind resultLevelKind)
        {
            resultLevelKind = new ResultLevelKind
            {
                Level = FailureLevel.Note,
            };

            string id = fingerprint.Id;
            string secret = fingerprint.Secret;

            try
            {
                var iamClient = new AmazonIdentityManagementServiceClient(id, secret);

                GetAccountAuthorizationDetailsRequest request;
                GetAccountAuthorizationDetailsResponse response;

                request = new GetAccountAuthorizationDetailsRequest();
                response = iamClient.GetAccountAuthorizationDetailsAsync(request).GetAwaiter().GetResult();

                message = BuildAuthorizedMessage(id, response);
            }
            catch (AmazonIdentityManagementServiceException e)
            {
                switch (e.ErrorCode)
                {
                    case "AccessDenied":
                    {
                        FlexMatch match = RegexEngine.Match(e.Message, AwsUserExpression);

                        // May return a message containing user id details such as:
                        // User: arn:aws:iam::123456123456:user/example.com@@dead1234dead1234dead1234 is not
                        // authorized to perform: iam:GetAccountAuthorizationDetails on resource: *

                        if (match.Success)
                        {
                            int trimmedChars = "User: ".Length + "is not authorized ".Length;
                            string iamUser = match.Value.String.Substring("User: ".Length, match.Value.String.Length - trimmedChars);
                            message = $"the compromised AWS identity is '{iamUser}";
                        }

                        resultLevelKind.Level = FailureLevel.Error;
                        return ValidationState.AuthorizedError;
                    }

                    case "InvalidClientTokenId":
                    case "SignatureDoesNotMatch":
                    {
                        resultLevelKind.Level = FailureLevel.None;
                        return ValidationState.NoMatch;
                    }
                }

                message = $"An unexpected exception was caught attempting to authenticate AWS id '{id}': {e.Message}";
                return ValidationState.Unknown;
            }
            catch (Exception e)
            {
                message = $"An unexpected exception was caught attempting to authentic AWS id '{id}': {e.Message}";
                return ValidationState.Unknown;
            }

            resultLevelKind.Level = FailureLevel.Error;
            return ValidationState.AuthorizedError;
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
