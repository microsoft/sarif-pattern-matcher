// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using System.Xml;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class NuGetCredentialsValidatorTests
    {
        private const ValidationState ExpectedValidationState = ValidationState.Unknown;

        [Fact]
        public void NuGetCredentialsValidator_Test()
        {
            string fingerprintText = "[host=<packageSources>\n    <clear />\n    <add key=\"sourceName\" value=\"https://api.nuget.org/v3/index.json\" />\n  </packageSources>][id=username][secret=password]";
            var fingerprint = new Fingerprint(fingerprintText);
            string message = null;
            ResultLevelKind resultLevelKind = default;
            var keyValuePairs = new Dictionary<string, string>();

            ValidationState actualValidationState = NuGetCredentialsValidator.IsValidDynamic(ref fingerprint, ref message, keyValuePairs, ref resultLevelKind);
            Assert.Equal(ExpectedValidationState, actualValidationState);
        }

        [Fact]
        public void ExtractHostsWorksOnCommonFormat()
        {
            string xmlString = @"<packageSources>
    <add key=""nuget.org"" value=""https://api.nuget.org/v3/index.json"" protocolVersion=""3"" />
    <add key = ""Contoso"" value = ""https://contoso.com/packages/"" />

       <add key = ""Test Source"" value = ""c:\packages"" />
      </packageSources> ";

            List<string> hosts = NuGetCredentialsValidator.ExtractHosts(xmlString);

            Assert.Equal(3, hosts.Count());
            Assert.Contains("https://api.nuget.org/v3/index.json", hosts);
            Assert.Contains("https://contoso.com/packages/", hosts);
            Assert.Contains(@"c:\packages", hosts);
        }

        [Fact]
        public void ExtractHostsWorksOnUnCommonFormat()
        {
            string xmlString = @"<packageSources>\nstuff\n<\/packageSources>";

            List<string> hosts = NuGetCredentialsValidator.ExtractHosts(xmlString);

            Assert.Single(hosts);
            Assert.Contains("stuff", hosts);
        }
    }
}
