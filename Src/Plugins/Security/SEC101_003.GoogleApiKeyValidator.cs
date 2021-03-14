// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using GoogleApi.Entities.Common;
using GoogleApi.Entities.Maps.Directions.Request;
using GoogleApi.Exceptions;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GoogleApiKeyValidator : ValidatorBase
    {
        internal static GoogleApiKeyValidator Instance;

        static GoogleApiKeyValidator()
        {
            Instance = new GoogleApiKeyValidator();
        }

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
            fingerprintText = new Fingerprint
            {
                Key = matchedPattern,
                Platform = nameof(AssetPlatform.Google),
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            const string Invalid = "RequestDenied: The provided API key is invalid";
            const string Expired = "RequestDenied: The provided API key is expired";
            const string RevokedKey = "RequestDenied: Google has disabled the use of APIs from this API project";
            const string ProjectNotAuthorized = "RequestDenied: This API project is not authorized to use this API";
            const string KeyNotAuthorized = "RequestDenied: This API key is not authorized to use this service or API";
            const string RefererRestrictions = "RequestDenied: API keys with referer restrictions cannot be used with this API";
            const string IpNotAuthorized = "RequestDenied: This IP, site or mobile application is not authorized to use this API key";
            const string EnableBilling = "RequestDenied: You must enable Billing on the Google Cloud Project at https://console.cloud.google.com/project/_/billing/enable Learn more at https://developers.google.com/maps/gmp-get-started";
            const string Deleted = "RequestDenied: This API project was not found. This API project may have been deleted or may not be authorized to use this API. You may need to enable the API under APIs in the console";

            var fingerprint = new Fingerprint(fingerprintText);

            string apiKey = fingerprint.Key;

            var request = new DirectionsRequest
            {
                Key = apiKey,
                Origin = new Location("Seattle"),
                Destination = new Location("Portland"),
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
                        e.Message.StartsWith(IpNotAuthorized) ||
                        e.Message.StartsWith(RefererRestrictions))
                    {
                        return nameof(ValidationState.Unauthorized);
                    }

                    if (e.Message.StartsWith(Deleted) ||
                        e.Message.StartsWith(Expired))
                    {
                        return nameof(ValidationState.Expired);
                    }

                    if (e.Message.StartsWith(EnableBilling))
                    {
                        // The API is enabled but billing has not been configured.
                        return nameof(ValidationState.AuthorizedError);
                    }

                    if (e.Message.StartsWith(KeyNotAuthorized) ||
                        e.Message.StartsWith(ProjectNotAuthorized))
                    {
                        // What this condition means is that the API key is recognized.
                        // It is not authorized for the Directions API, but this isn't
                        // what we're verifying here.
                        return nameof(ValidationState.AuthorizedError);
                    }

                    if (e.Message.StartsWith(Invalid))
                    {
                        return nameof(ValidationState.NoMatch);
                    }
                }

                message = $"An unexpected exception was caught attempting to validate api key: {e.Message}";
                return nameof(ValidationState.Unknown);
            }

            // This condition indicates the API key is recognized and can access Directions API.
            return nameof(ValidationState.AuthorizedError);
        }
    }
}
