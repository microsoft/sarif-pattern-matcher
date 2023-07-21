// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    [ValidatorDescriptor("SEC101/008")]
    public class AwsCredentialsValidator : DynamicValidatorBase
    {
        internal static IRegex RegexEngine;

        private const string UserPrefix = "User: ";
        private const string UserSuffix = " is not authorized";
        private static readonly string AwsUserExpression = $"^{UserPrefix}.+?{UserSuffix}";

        public AwsCredentialsValidator()
        {
            RegexEngine = RE2Regex.Instance;

            RegexEngine.IsMatch(string.Empty, AwsUserExpression);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Id = id.Value,
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.Aws),
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

                        return ValidationState.Authorized;
                    }

                    case "InvalidClientTokenId":
                    case "SignatureDoesNotMatch":
                    {
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

            return ValidationState.Authorized;
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
