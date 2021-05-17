// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
    }
}
