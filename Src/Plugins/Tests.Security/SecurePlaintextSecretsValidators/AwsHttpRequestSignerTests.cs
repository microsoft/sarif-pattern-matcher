// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

using FluentAssertions;
using FluentAssertions.Execution;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class AwsHttpRequestSignerTests
    {
        [Fact]
        public void SignRequest_Tests()
        {
            string id = "ASIAABC";
            string secret = "abc";
            string service = "service";
            string region = "us-east-1";
            string endpointUri = "https://service.example.com";
            DateTime timestamp = DateTime.UtcNow;

            using var signer = new AwsHttpRequestSigner(id, secret);
            using var request = new HttpRequestMessage(HttpMethod.Get, endpointUri);
            signer.SignRequest(request, service, region, timestamp);

            using (new AssertionScope())
            {
                request.Headers.Should().HaveCount(4);
                request.Headers.TryGetValues(signer.HostHeaderName, out IEnumerable<string> hostValues).Should().BeTrue();
                request.Headers.TryGetValues(signer.DateHeaderName, out IEnumerable<string> dateValues).Should().BeTrue();
                request.Headers.TryGetValues(signer.ContentSha256HeaderName, out IEnumerable<string> sha256Values).Should().BeTrue();
                request.Headers.TryGetValues("Authorization", out IEnumerable<string> authValues).Should().BeTrue();

                hostValues.First().Should().Be(new Uri(endpointUri).Host);
                dateValues.First().Should().Be(timestamp.ToString("yyyyMMddTHHmmssZ"));
                sha256Values.First().Length.Should().BeGreaterThan(1);
                authValues.First().Should().StartWith(signer.Algorithm);
            }
        }

        [Fact]
        public void Ctor_Tests()
        {
            string id = "ASIAABC";
            string secret = "abc";

            Action act = null;
            using (new AssertionScope())
            {
                act = () => new AwsHttpRequestSigner(null, secret);
                act.Should().Throw<ArgumentNullException>().WithParameterName("accessKey");

                act = () => new AwsHttpRequestSigner(id, null);
                act.Should().Throw<ArgumentNullException>().WithParameterName("secretKey");

                act = () => new AwsHttpRequestSigner(id, secret);
                act.Should().NotThrow();
            }
        }

        [Fact]
        public void SignRequest_NullArguments_Tests()
        {
            string id = "ASIAABC";
            string secret = "abc";
            string service = "service";
            string region = "us-east-1";
            string endpointUri = "https://service.example.com";

            using var signer = new AwsHttpRequestSigner(id, secret);
            using var request = new HttpRequestMessage(HttpMethod.Get, endpointUri);

            Action act = null;
            using (new AssertionScope())
            {
                act = () => signer.SignRequest(null, region, service);
                act.Should().Throw<ArgumentNullException>().WithParameterName("request");

                act = () => signer.SignRequest(request, null, service);
                act.Should().Throw<ArgumentNullException>().WithParameterName("region");

                act = () => signer.SignRequest(request, region, null);
                act.Should().Throw<ArgumentNullException>().WithParameterName("service");

                act = () => signer.SignRequest(request, region, service);
                act.Should().NotThrow();
            }
        }
    }
}
