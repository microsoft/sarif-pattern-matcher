// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public static class SharedUtilities
    {
        public static void PopulateAssetFingerprint(string host, ref Fingerprint fingerprint, List<string> azureHosts = null)
        {
            if (GetDatabasePlatformFromHost(host, out _, azureHosts) != nameof(AssetPlatform.Azure))
            {
                fingerprint.Platform = nameof(AssetPlatform.SqlOnPremise);
                return;
            }

            fingerprint.Part = "servers";
            fingerprint.Platform = nameof(AssetPlatform.Azure);
        }

        public static string GetDatabasePlatformFromHost(string host, out string resource, List<string> platformHosts = null)
        {
            resource = null;

            var list = new List<string>
            {
                ".database.windows.net",
                ".database.azure.com",
            };

            if (platformHosts != null)
            {
                list.AddRange(platformHosts);
            }

            foreach (string item in list)
            {
                string result = ExtractResource(item, host, out resource);
                if (!string.IsNullOrEmpty(result))
                {
                    return result;
                }
            }

            return nameof(AssetPlatform.SqlOnPremise);
        }

        private static string ExtractResource(string pattern, string host, out string resource)
        {
            resource = null;

            int indexOf = host.IndexOf(pattern);
            if (indexOf >= 0)
            {
                resource = host.Substring(0, indexOf);
                return nameof(AssetPlatform.Azure);
            }

            return string.Empty;
        }
    }
}
