// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    [ValidatorDescriptor("SEC101/003")]
    public class GoogleApiKeyValidator : DynamicValidatorBase
    {
        internal const string EndpointUriTemplate = "https://maps.googleapis.com/maps/api/directions/json?key={0}&origin=Seattle&destination=Redmond&units=metric&language=en&mode=driving";

        protected override string Platform => nameof(AssetPlatform.Google);

        protected override bool IsFalsePositiveOrBelongsToOtherSecurityModel(string secret)
        {
            // It is highly likely we do not have a key if we can't
            // find at least one letter and digit within the pattern.
            return !secret.ContainsDigitAndLetter();
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            const string RequestDeniedErrorCode = "REQUEST_DENIED";
            const string Invalid = "The provided API key is invalid";
            const string Expired = "The provided API key is expired";
            const string RevokedKey = "Google has disabled the use of APIs from this API project";
            const string ProjectNotAuthorized = "This API project is not authorized to use this API";
            const string KeyNotAuthorized = "This API key is not authorized to use this service or API";
            const string RefererRestrictions = "API keys with referer restrictions cannot be used with this API";
            const string IPNotAuthorized = "This IP, site or mobile application is not authorized to use this API key";
            const string EnableBilling = "You must enable Billing on the Google Cloud Project at https://console.cloud.google.com/project/_/billing/enable Learn more at https://developers.google.com/maps/gmp-get-started";
            const string Deleted = "This API project was not found. This API project may have been deleted or may not be authorized to use this API. You may need to enable the API under APIs in the console";

            string apiKey = fingerprint.Secret;
            string endpointUrl = string.Format(EndpointUriTemplate, apiKey);

            try
            {
                HttpClient client = CreateOrRetrieveCachedHttpClient();

                using var request = new HttpRequestMessage(HttpMethod.Get, endpointUrl);

                request.Headers.Add("Accept", "application/json");

                using HttpResponseMessage response = client.ReadResponseHeaders(request);

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        string responseJson = response.Content.ReadAsStringAsync().Result;

                        if (this.CheckResponseIfSucceeded(responseJson,
                                                          out string errorCode,
                                                          out string errorMessage))
                        {
                            // This condition indicates the API key is recognized and can access Directions API.
                            return ValidationState.Authorized;
                        }

                        StringComparison ignoreCase = StringComparison.OrdinalIgnoreCase;

                        if (errorCode.Equals(RequestDeniedErrorCode, ignoreCase))
                        {
                            if (errorMessage.StartsWith(RevokedKey, ignoreCase) ||
                                errorMessage.StartsWith(IPNotAuthorized, ignoreCase) ||
                                errorMessage.StartsWith(RefererRestrictions, ignoreCase))
                            {
                                return ValidationState.Unauthorized;
                            }

                            if (errorMessage.StartsWith(Deleted, ignoreCase) ||
                                errorMessage.StartsWith(Expired, ignoreCase))
                            {
                                return ValidationState.Expired;
                            }

                            if (errorMessage.StartsWith(EnableBilling, ignoreCase))
                            {
                                // The API is enabled but billing has not been configured.
                                return ValidationState.Authorized;
                            }

                            if (errorMessage.StartsWith(KeyNotAuthorized, ignoreCase) ||
                                errorMessage.StartsWith(ProjectNotAuthorized, ignoreCase))
                            {
                                // What this condition means is that the API key is recognized.
                                // It is not authorized for the Directions API, but this isn't
                                // what we're verifying here.
                                return ValidationState.Authorized;
                            }

                            if (errorMessage.StartsWith(Invalid, ignoreCase))
                            {
                                return ValidationState.NoMatch;
                            }
                        }

                        message = $"An unexpected exception was caught attempting to validate api key: {errorCode}: {errorMessage}";
                        return ValidationState.Unknown;
                    }

                    default:
                    {
                        return ReturnUnexpectedResponseCode(ref message, response.StatusCode);
                    }
                }
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e, apiKey.Truncate());
            }
        }

        private bool CheckResponseIfSucceeded(string responseJson, out string errorCode, out string errorMessage)
        {
            errorCode = errorMessage = string.Empty;

            try
            {
                var responseObject = JObject.Parse(responseJson);

                if (responseObject["status"] != null &&
                    responseObject["error_message"] != null)
                {
                    errorCode = (string)responseObject["status"];
                    errorMessage = (string)responseObject["error_message"];
                    return false;
                }

                return responseObject["routes"] != null;
            }
            catch (JsonReaderException)
            {
                return false;
            }
        }
    }
}
