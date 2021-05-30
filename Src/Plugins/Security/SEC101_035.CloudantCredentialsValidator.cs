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
    public class CloudantCredentialsValidator : ValidatorBase
    {
        internal static CloudantCredentialsValidator Instance;

        static CloudantCredentialsValidator()
        {
            Instance = new CloudantCredentialsValidator();
        }

        public static IEnumerable<ValidationResult> IsValidStatic(Dictionary<string, FlexMatch> groups)
        {
            return IsValidStatic(Instance, groups);
        }

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     Dictionary<string, string> options,
                                                     ref ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  options,
                                  ref resultLevelKind);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(Dictionary<string, FlexMatch> groups)
        {
            // We need uri and neither account nor password, or uri and both account and password.  Use XOR
            if (!groups.TryGetNonEmptyValue("id", out FlexMatch id) ||
                !groups.TryGetNonEmptyValue("host", out FlexMatch host) ||
                !groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            groups.TryGetNonEmptyValue("resource", out FlexMatch resource);

            var validationResult = new ValidationResult
            {
                RegionFlexMatch = secret,
                Fingerprint = new Fingerprint()
                {
                    Id = id.Value,
                    Host = host.Value,
                    Secret = secret.Value,
                    Resource = resource?.Value,
                    Platform = nameof(AssetPlatform.Cloudant),
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                Dictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            // TODO: Create a unit test for this. https://github.com/microsoft/sarif-pattern-matcher/issues/258

            string id = fingerprint.Id;
            string host = fingerprint.Host;
            string secret = fingerprint.Secret;
            string resource = fingerprint.Resource ?? id;
            string asset = $"{resource}.{host}";

            try
            {
                string uri = $"https://{asset}";

                var handler = new HttpClientHandler
                {
                    Credentials = new NetworkCredential(ScanIdentityId, ScanIdentityId),
                };

                using var clientWithNoCredentials = new HttpClient(handler)
                {
                    BaseAddress = new Uri(uri),
                };

                using HttpResponseMessage responseWithNoCredentials = clientWithNoCredentials
                    .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                if (responseWithNoCredentials.StatusCode == HttpStatusCode.OK)
                {
                    // If we succeed with a known invalid id + secret combination,
                    // some level of anonymous access must be configured.
                    return ValidationState.NoMatch;
                }

                handler = new HttpClientHandler
                {
                    Credentials = new NetworkCredential(id, secret),
                };

                using var client = new HttpClient(handler)
                {
                    BaseAddress = new Uri(uri),
                };

                using HttpResponseMessage response = client
                    .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead)
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return ReturnAuthorizedAccess(ref message, asset);
                    }

                    case HttpStatusCode.ServiceUnavailable:
                    {
                        return ReturnUnknownHost(ref message, asset);
                    }

                    case HttpStatusCode.Unauthorized:
                    {
                        return ReturnUnauthorizedAccess(ref message, asset);
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode, asset);
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
