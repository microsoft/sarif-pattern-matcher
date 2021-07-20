// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class SharedUtilitiesTests
    {
        [Fact]
        public void SharedUtilities_PopulateAssetFingerprint()
        {
            var fingerprint = new Fingerprint();
            string[] azureHosts = new string[]
            {
                "resource.database.windows.net",
                "resource.database.azure.com",
            };

            foreach (string azureHost in azureHosts)
            {
                SharedUtilities.PopulateAssetFingerprint(azureHost, ref fingerprint);
                fingerprint.Part.Should().Be("servers");
                fingerprint.Platform.Should().Be(nameof(AssetPlatform.Azure));
            }

            SharedUtilities.PopulateAssetFingerprint("some-unknown-host", ref fingerprint);
            fingerprint.Part.Should().Be("servers");
            fingerprint.Platform.Should().Be(nameof(AssetPlatform.SqlOnPremise));
        }

        [Fact]
        public void SharedUtilities_PopulateAssetFingerprint_WithHostList()
        {
            var fingerprint = new Fingerprint();
            string[] azureHosts = new string[]
            {
                "resource.database.windows.net",
                "resource.database.azure.com",
                "mysqldb.chinacloudapi.cn",
                "mysql.database.azure.com",
            };

            var otherAzureHosts = new List<string>
            {
                "mysqldb.chinacloudapi.cn",
                "mysql.database.azure.com",
            };

            foreach (string azureHost in azureHosts)
            {
                SharedUtilities.PopulateAssetFingerprint(otherAzureHosts, azureHost, ref fingerprint);
                fingerprint.Part.Should().Be("servers");
                fingerprint.Platform.Should().Be(nameof(AssetPlatform.Azure));
            }

            SharedUtilities.PopulateAssetFingerprint(otherAzureHosts, "some-unknown-host", ref fingerprint);
            fingerprint.Part.Should().Be("servers");
            fingerprint.Platform.Should().Be(nameof(AssetPlatform.SqlOnPremise));
        }
    }
}
