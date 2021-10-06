// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.AzureDevOpsConfiguration
{
    public class DoNotGrantAllPipelinesAccessValidator : DynamicValidatorBase
    {
        internal const string PipelinePermissionAPI = "https://{0}/{1}/_apis/pipelines/pipelinePermissions/endpoint/{2}?api-version=6.1-preview.1";
        internal const string NotAuthorizedMessage = "Not able to access required ADO API to check.";
        private const string AdoPatFile = "AdoPat.txt";
        private static string adoPat = null;

        internal static ValidationState VerifyResponse(string response, ref string message)
        {
            PipelinePermission pipelinePermission = JsonConvert.DeserializeObject<PipelinePermission>(response);
            bool? authorized = pipelinePermission?.AllPipelines?.Authorized;
            if (authorized != null && authorized.Value == true)
            {
                // its shared to all pipelines
                message = "Was found its accssible to all pipelines.";
                return ValidationState.Authorized;
            }
            else
            {
                return ValidationState.NoMatch;
            }
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetValue("org", out FlexMatch org) ||
                !groups.TryGetValue("project", out FlexMatch project) ||
                !groups.TryGetValue("serviceConnectionId", out FlexMatch serviceConnectionId))
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Host = org.Value.String,
                    Resource = project.Value.String,
                    Id = serviceConnectionId.Value.String,
                    Platform = nameof(AssetPlatform.AzureDevOps),
                },
                ValidationState = ValidationState.Unknown,
            };
            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                IDictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            try
            {
                string organization = fingerprint.Host;
                string project = fingerprint.Resource;
                string serviceConnectionId = fingerprint.Id;

                adoPat ??= ReadPatFromFile(AdoPatFile);
                if (string.IsNullOrEmpty(adoPat))
                {
                    return ValidationState.Unauthorized;
                }

                HttpClient httpClient = CreateOrRetrieveCachedHttpClient();
                httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                    Convert.ToBase64String(
                        ASCIIEncoding.ASCII.GetBytes(
                            string.Format("{0}:{1}", string.Empty, adoPat))));

                // since DynamicValidatorBase already has a cache for <fingerprint, result>
                // IsValidDynamicHelper will not be called if same fingerprint combinations,
                // do not need cache for same organization/project/seviceconnectionid combination
                using HttpResponseMessage response = httpClient.GetAsync(
                    string.Format(PipelinePermissionAPI, organization, project, serviceConnectionId))
                    .GetAwaiter()
                    .GetResult();

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                    {
                        return VerifyResponse(
                            response.Content.ReadAsStringAsync().GetAwaiter().GetResult(),
                            ref message);
                    }

                    case HttpStatusCode.Unauthorized:
                    case HttpStatusCode.Forbidden:
                    {
                        message = NotAuthorizedMessage;
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
                return ReturnUnhandledException(ref message, e);
            }
        }

        private static string ReadPatFromFile(string fileName)
        {
            // exception will be catched by caller
            string path = System.IO.Path.Combine(
                System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location),
                fileName);

            return System.IO.File.ReadAllText(path);
        }

        // used by unit tests
        internal void SetAdoPat(string pat)
        {
            adoPat = pat;
        }

        // ignore other properties since we do not use them now.
        internal class PipelinePermission
        {
            [JsonProperty("allPipelines")]
            public AllPipeLines AllPipelines { get; set; }
        }

        internal class AllPipeLines
        {
            [JsonProperty("authorized")]
            public bool Authorized { get; set; }
        }
    }
}
