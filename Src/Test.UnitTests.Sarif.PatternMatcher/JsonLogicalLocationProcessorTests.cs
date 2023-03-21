// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

using FluentAssertions;

using Microsoft.RE2.Managed;

using Newtonsoft.Json;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Test.Processors
{
    public class JsonLogicalLocationProcessorTests
    {
        private readonly JsonLogicalLocationProcessor processor;

        public JsonLogicalLocationProcessorTests()
        {
            this.processor = new JsonLogicalLocationProcessor();
        }

        private const string SampleJsonContent = @"
{
    ""stuff"":
    [
        { ""name"": ""value"" },
        145, true, null,
        { ""second"": ""secondValue"" },
        { ""nested"": { ""space in name"": [""stringValue""] } }
    ]
}";

        [Fact]
        public void JsonLogicalLocation_Basics()
        {
            IRegex engine = RE2Regex.Instance;

            // Property Name
            ResolveJsonLogicalPath(SampleJsonContent, "name", "stuff[0].name");

            // Property String Value
            ResolveJsonLogicalPath(SampleJsonContent, "value", "stuff[0].name");

            // Direct Array values
            ResolveJsonLogicalPath(SampleJsonContent, "145", "stuff[1]");
            ResolveJsonLogicalPath(SampleJsonContent, "4", "stuff[1]");
            ResolveJsonLogicalPath(SampleJsonContent, "true", "stuff[2]");

            // Spanning Property+Value
            ResolveJsonLogicalPath(SampleJsonContent, @"me"": ""val", "stuff[0].name");

            // Object within array
            ResolveJsonLogicalPath(SampleJsonContent, @"{ ""se", "stuff[4]");

            // Root object
            ResolveJsonLogicalPath(SampleJsonContent, "stuff", "stuff");

            // Root object
            ResolveJsonLogicalPath(SampleJsonContent, "stringValue", "stuff[5].nested['space in name'][0]");
        }

        private void ResolveJsonLogicalPath(string fileContent, string valueToFind, string expectedJsonPath)
        {
            int index = fileContent.IndexOf(valueToFind);
            Assert.True(index != 1);

            var region = new Region
            {
                CharOffset = index,
                CharLength = valueToFind.Length
            };

            var result = new Result();
            result.Locations = new List<Location>();
            result.Locations.Add(new Location());
            result.Locations[0].PhysicalLocation = new PhysicalLocation()
            {
                ArtifactLocation = new ArtifactLocation()
                {
                    Uri = new Uri($"c:\\{Guid.NewGuid()}.txt")
                }
            };

            result.Locations[0].PhysicalLocation.Region = region;

            // TODO: Our JSON logical path processor currently depends on line locations.
            //       We should update the logical to permit operation against char lengths.
            var fileRegionsCache = new FileRegionsCache();
            result.Locations[0].PhysicalLocation.Region =
                fileRegionsCache.PopulateTextRegionProperties(region, new Uri("file://unused.txt"), true, fileContent);

            // Run the processor to identify the Json path
            processor.Process(new[] { result }, fileContent);

            Assert.Equal(expectedJsonPath, result.Locations[0].LogicalLocation.FullyQualifiedName);
        }

        [Fact]
        public void JsonLogicalLocationProcessor_ToFingerprint()
        {
            Assert.Null(JsonLogicalLocationProcessor.ToFingerprint(null));
            Assert.Null(JsonLogicalLocationProcessor.ToFingerprint(""));

            Assert.Equal("tool.toolName", JsonLogicalLocationProcessor.ToFingerprint("tool.toolName"));
            Assert.Equal("runs[].results[]", JsonLogicalLocationProcessor.ToFingerprint("runs[0].results[15]"));
            Assert.Equal("runs[].results[].message.text", JsonLogicalLocationProcessor.ToFingerprint("runs[0].results[15].message.text"));
            Assert.Equal("[]", JsonLogicalLocationProcessor.ToFingerprint("[15]"));
            Assert.Null(JsonLogicalLocationProcessor.ToFingerprint("[15"));
        }

        [Fact]
        public void JsonLogicalProcessor_ResultsOutOfOrder()
        {
            // Regression test for:
            // https://dev.azure.com/mseng/1ES/_workitems/edit/2040914
            //
            // Fix shipped in 4.3.3.

            string fileContents = "{\r\n  \"variables\": {\r\n    \"firstInFile\": {\r\n      \"value\": \"1/000000000000000:deaddeaddeaddeaddeaddeaddeaddead\"\r\n    },\r\n    \"system.debug\": {\r\n      \"value\": \"true\",\r\n      \"allowOverride\": true\r\n    },\r\n    \"secondInFile\": {\r\n      \"value\": \"deadpat0deadpat0deadpat0deadpat0deadpat0deadpat0dead\"\r\n    }\r\n  }\r\n}";
            string serializedResults = "[{\"ruleId\":\"SEC101/102\",\"level\":\"error\",\"message\":{\"id\":\"Default\",\"arguments\":[\"…p2izpq\",\"an apparent \",\"\",\"Azure DevOps personal access token (PAT)\",\"\",\"\"]},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"file:///d:/testfiles/repro.json\"},\"region\":{\"startLine\":11,\"startColumn\":17,\"endLine\":11,\"endColumn\":69,\"charOffset\":243,\"charLength\":52,\"snippet\":{\"text\":\"deadpat0deadpat0deadpat0deadpat0deadpat0deadpat0dead\"}},\"contextRegion\":{\"startLine\":10,\"startColumn\":1,\"endLine\":12,\"endColumn\":6,\"charOffset\":204,\"charLength\":99,\"snippet\":{\"text\":\"    \\\"secondInFile\\\": {\\r\\n      \\\"value\\\": \\\"deadpat0deadpat0deadpat0deadpat0deadpat0deadpat0dead\\\"\\r\\n    }\"}}}}],\"fingerprints\":{\"secretHashSha256/v0\":\"9307d491acfa06793dfb54bd90f0bef1859fc6e3caacf6a4f496c1a3d1dfc56a\",\"assetFingerprint/v0\":\"{\\\"platform\\\":\\\"AzureDevOps\\\"}\",\"validationFingerprintHashSha256/v0\":\"90ecd2b4cacbfb53e5aee13addaac7ebbb5389658d5cb93d116beeff4a402988\",\"secretFingerprint/v0\":\"{\\\"secret\\\":\\\"deadpat0deadpat0deadpat0deadpat0deadpat0deadpat0dead\\\"}\",\"validationFingerprint/v0\":\"{\\\"secret\\\":\\\"deadpat0deadpat0deadpat0deadpat0deadpat0deadpat0dead\\\"}\"},\"rank\":63.02},{\"ruleId\":\"SEC101/504\",\"message\":{\"id\":\"Default\",\"arguments\":[\"…addead\",\"an apparent \",\"\",\"Asana personal access token\",\"\",\"\"]},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"file:///d:/testfiles/repro.json\"},\"region\":{\"startLine\":4,\"startColumn\":17,\"endLine\":4,\"endColumn\":67,\"charOffset\":59,\"charLength\":50,\"snippet\":{\"text\":\"1/000000000000000:deaddeaddeaddeaddeaddeaddeaddead\"}},\"contextRegion\":{\"startLine\":3,\"startColumn\":1,\"endLine\":5,\"endColumn\":7,\"charOffset\":21,\"charLength\":97,\"snippet\":{\"text\":\"    \\\"firstInFile\\\": {\\r\\n      \\\"value\\\": \\\"1/000000000000000:deaddeaddeaddeaddeaddeaddeaddead\\\"\\r\\n    },\"}}}}],\"fingerprints\":{\"secretHashSha256/v0\":\"ed1ae91ea40454506c72a6b4b065c6259b2f5e1cb636db3a8d7e23e49f486c85\",\"assetFingerprint/v0\":\"{\\\"platform\\\":\\\"Asana\\\"}\",\"validationFingerprintHashSha256/v0\":\"c57f113b230e27a46530b64e3cd4e923e1ddc272b705a64b260afe4f3bedd0d9\",\"secretFingerprint/v0\":\"{\\\"secret\\\":\\\"1/000000000000000:deaddeaddeaddeaddeaddeaddeaddead\\\"}\",\"validationFingerprint/v0\":\"{\\\"secret\\\":\\\"1/000000000000000:deaddeaddeaddeaddeaddeaddeaddead\\\"}\"},\"rank\":31.88}]";
            ICollection<Result> results = JsonConvert.DeserializeObject<ICollection<Result>>(serializedResults);

            var processor = new JsonLogicalLocationProcessor();
            processor.Process(results, fileContents);

            var expectedPaths = new HashSet<string>(new[]
                {
                    "variables.firstInFile.value",
                    "variables.secondInFile.value"
                });

            var actualPaths = new HashSet<string>();

            foreach (Result result in results)
            {
                actualPaths.Add(result.Locations[0].LogicalLocation.FullyQualifiedName);
            }

            expectedPaths.Should().BeEquivalentTo(actualPaths);
        }
    }
}
