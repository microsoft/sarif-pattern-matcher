// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Xml;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    [ValidatorDescriptor("SEC101/008")]
    public class AwsCredentialsValidator : DynamicValidatorBase
    {
        internal DateTime TimeStamp;
        private const string UserPrefix = "User: ";
        private const string UserSuffix = " is not authorized";
        private static readonly string AwsUserExpression = $"^{UserPrefix}.+?{UserSuffix}";

        public AwsCredentialsValidator()
        {
            RegexInstance.IsMatch(string.Empty, AwsUserExpression);

            this.TimeStamp = DateTime.UtcNow;
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
            const string endpointUri = "https://iam.amazonaws.com/";
            const string payload = "Action=GetAccountAuthorizationDetails&Version=2010-05-08";

            try
            {
                HttpClient client = CreateOrRetrieveCachedHttpClient();

                using var request = new HttpRequestMessage(HttpMethod.Post, endpointUri);

                request.Content = new StringContent(payload, Encoding.UTF8, "application/x-www-form-urlencoded");

                using var requestSigner = new AwsHttpRequestSigner(id, secret);

                requestSigner.SignRequest(request, "us-east-1", "iam", this.TimeStamp);

                using HttpResponseMessage response = client.ReadResponseHeaders(request);

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        Stream responseStream = response.Content.ReadAsStreamAsync().Result;

                        message = BuildAuthorizedMessage(id, responseStream);

                        return ValidationState.Authorized;
                    }

                    case HttpStatusCode.Forbidden:
                    {
                        Stream responseStream = response.Content.ReadAsStreamAsync().Result;

                        ReadErrorCodeMessage(responseStream, out string errorCode, out string errorMessage);

                        switch (errorCode)
                        {
                            case "AccessDenied":
                            {
                                FlexMatch match = RegexInstance.Match(errorMessage, AwsUserExpression);

                                // May return a message containing user id details such as:
                                // User: arn:aws:iam::123456123456:user/example.com@@dead1234dead1234dead1234 is not
                                // authorized to perform: iam:GetAccountAuthorizationDetails on resource: *

                                if (match.Success)
                                {
                                    int trimmedChars = UserPrefix.Length + UserSuffix.Length;
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

                        return ValidationState.Unauthorized;
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode, id);
                    }
                }
            }
            catch (Exception e)
            {
                message = $"An unexpected exception was caught attempting to authenticate AWS id '{id}': {e.Message}";
                return ValidationState.Unknown;
            }
        }

        private string BuildAuthorizedMessage(string id, Stream responseStream)
        {
            var policyNames = new List<string>();

            using var reader = XmlReader.Create(responseStream);

            if (reader.ReadToFollowing("Policies"))
            {
                using XmlReader policyReader = reader.ReadSubtree();

                while (policyReader.ReadToFollowing("member"))
                {
                    if (policyReader.ReadToFollowing("PolicyName"))
                    {
                        policyNames.Add(reader.ReadElementContentAsString());
                    }
                }
            }

            string policyNamesText = string.Join(", ", policyNames);

            return $"id '{id}' is authorized for role policies '{policyNamesText}'.";
        }

        private void ReadErrorCodeMessage(Stream responseStream, out string code, out string message)
        {
            code = message = string.Empty;

            using var reader = XmlReader.Create(responseStream);

            if (reader.ReadToFollowing("Code"))
            {
                code = reader.ReadElementContentAsString();
            }

            if (reader.ReadToFollowing("Message"))
            {
                message = reader.ReadElementContentAsString();
            }
        }
    }
}
