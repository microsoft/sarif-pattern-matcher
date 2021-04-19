// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using GoogleApi.Entities.Common;
using GoogleApi.Entities.Maps.Directions.Request;
using GoogleApi.Exceptions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GoogleApiKeyValidator : ValidatorBase
    {
        internal static GoogleApiKeyValidator Instance;

        static GoogleApiKeyValidator()
        {
            Instance = new GoogleApiKeyValidator();
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
            resultLevelKind = default;
            fingerprint = new Fingerprint
            {
                Secret = matchedPattern,
                Platform = nameof(AssetPlatform.Google),
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

            const string Invalid = "RequestDenied: The provided API key is invalid";
            const string Expired = "RequestDenied: The provided API key is expired";
            const string RevokedKey = "RequestDenied: Google has disabled the use of APIs from this API project";
            const string ProjectNotAuthorized = "RequestDenied: This API project is not authorized to use this API";
            const string KeyNotAuthorized = "RequestDenied: This API key is not authorized to use this service or API";
            const string RefererRestrictions = "RequestDenied: API keys with referer restrictions cannot be used with this API";
            const string IPNotAuthorized = "RequestDenied: This IP, site or mobile application is not authorized to use this API key";
            const string EnableBilling = "RequestDenied: You must enable Billing on the Google Cloud Project at https://console.cloud.google.com/project/_/billing/enable Learn more at https://developers.google.com/maps/gmp-get-started";
            const string Deleted = "RequestDenied: This API project was not found. This API project may have been deleted or may not be authorized to use this API. You may need to enable the API under APIs in the console";

            string apiKey = fingerprint.Secret;

            var request = new DirectionsRequest
            {
                Key = apiKey,
                Origin = new GoogleApi.Entities.Common.Location("Seattle"),
                Destination = new GoogleApi.Entities.Common.Location("Portland"),
            };

            try
            {
                GoogleApi.GoogleMaps.Directions.Query(request);
            }
            catch (Exception e)
            {
                if (e is GoogleApiException)
                {
                    if (e.Message.StartsWith(RevokedKey) ||
                        e.Message.StartsWith(IPNotAuthorized) ||
                        e.Message.StartsWith(RefererRestrictions))
                    {
                        return ValidationState.Unauthorized;
                    }

                    if (e.Message.StartsWith(Deleted) ||
                        e.Message.StartsWith(Expired))
                    {
                        return ValidationState.Expired;
                    }

                    if (e.Message.StartsWith(EnableBilling))
                    {
                        resultLevelKind.Level = FailureLevel.Error;

                        // The API is enabled but billing has not been configured.
                        return ValidationState.AuthorizedError;
                    }

                    if (e.Message.StartsWith(KeyNotAuthorized) ||
                        e.Message.StartsWith(ProjectNotAuthorized))
                    {
                        resultLevelKind.Level = FailureLevel.Error;

                        // What this condition means is that the API key is recognized.
                        // It is not authorized for the Directions API, but this isn't
                        // what we're verifying here.
                        return ValidationState.AuthorizedError;
                    }

                    if (e.Message.StartsWith(Invalid))
                    {
                        resultLevelKind.Level = FailureLevel.None;
                        return ValidationState.NoMatch;
                    }
                }

                message = $"An unexpected exception was caught attempting to validate api key: {e.Message}";
                return ValidationState.Unknown;
            }

            resultLevelKind.Level = FailureLevel.Error;

            // This condition indicates the API key is recognized and can access Directions API.
            return ValidationState.AuthorizedError;
        }
    }
}
