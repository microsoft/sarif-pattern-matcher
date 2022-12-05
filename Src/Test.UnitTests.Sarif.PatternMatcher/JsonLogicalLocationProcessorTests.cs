// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

using Microsoft.RE2.Managed;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Test.Processors
{
    public class JsonLogicalLocationProcessorTests
    {
        private JsonLogicalLocationProcessor processor;

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
            ResolveJsonLogicalPath(SampleJsonContent, "stringValue", "stuff");

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
            result.Locations[0].PhysicalLocation = new PhysicalLocation();
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
    }
}
