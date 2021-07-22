// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class SharedUtilitiesTests
    {
        [Fact]
        public void SharedUtilities_PopulateAssetFingerprint_WithHostList()
        {
            var testCases = new[]
            {
                new
                {
                    Host = "some-unknown-host",
                    ExpectedPart = (string)null,
                    ExpectedPlatform = "SqlOnPremise"
                },
                new
                {
                    Host = "resource.database.windows.net",
                    ExpectedPart = "servers",
                    ExpectedPlatform = "Azure"
                },
                new
                {
                    Host = "resource.database.azure.com",
                    ExpectedPart = "servers",
                    ExpectedPlatform = "Azure"
                },
                new
                {
                    Host = "mysqldb.chinacloudapi.cn",
                    ExpectedPart = "servers",
                    ExpectedPlatform = "Azure"
                },
                new
                {
                    Host = "mysql.database.azure.com",
                    ExpectedPart = "servers",
                    ExpectedPlatform = "Azure"
                }
            };

            var otherAzureHosts = new List<string>
            {
                "database.azure.com",
                "database.windows.net",
                "mysqldb.chinacloudapi.cn",
                "mysql.database.azure.com",
            };

            var sb = new StringBuilder();

            foreach (var testCase in testCases)
            {
                var fingerprint = new Fingerprint();
                SharedUtilities.PopulateAssetFingerprint(otherAzureHosts, testCase.Host, ref fingerprint);

                if (fingerprint.Part != testCase.ExpectedPart)
                {
                    sb.AppendLine($"Part should be '{testCase.ExpectedPart}' but it found '{fingerprint.Part}' for the host '{testCase.Host}'.");
                }

                if (fingerprint.Platform != testCase.ExpectedPlatform)
                {
                    sb.AppendLine($"Platform should be '{testCase.ExpectedPlatform}' but it found '{fingerprint.Platform}'  for the host '{testCase.Host}'.");
                }
            }

            sb.Length.Should().Be(0, sb.ToString());
        }
    }
}
