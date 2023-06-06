// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Linq;

using FluentAssertions;

using Moq;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    public class ExportSearchDefinitionsCommandTests
    {
        [Fact]
        public void ExportSearchDefinitionsCommand_ExportSingleBannedApi()
        {
            const string filePath = "file.txt";
            const string bannedApiInformation = @"<?xml version=""1.0"" encoding=""utf-8""?>
<ArrayOfContentSearcher xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
  <ContentSearcher>
    <Name>DoNotUseBannedApi</Name>
    <RuleId>BAN1001/Memory/Allocation/_alloca</RuleId>
    <ResourceMatchPattern>\.(c|cpp|cxx)$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>\b(?&lt;refine&gt;_alloca)\s*\(</string>
    </ContentSearchPatterns>
    <FullMatchDetails>'{0}' contains a call to '_alloca', a potentially insecure API that could be replaced with a more secure alternative: '_malloca'.</FullMatchDetails>
    <Severity>2</Severity>
  </ContentSearcher>
</ArrayOfContentSearcher>";

            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileReadAllText(filePath)).Returns(bannedApiInformation);

            // Act
            SearchDefinitions searchDefinitions = ExportSearchDefinitionsCommand.ExportBannedApi(mockFileSystem.Object, filePath);

            // Assert
            searchDefinitions.Should().NotBeNull();
            searchDefinitions.Definitions.Count.Should().Be(1);
            searchDefinitions.Definitions[0].MatchExpressions.Count(d => d.Level == FailureLevel.Warning).Should().Be(1);
        }

        [Fact]
        public void ExportSearchDefinitionsCommand_ExportMultipleBannedApi()
        {
            const string filePath = "file.txt";
            const string bannedApiInformation = @"<?xml version=""1.0"" encoding=""utf-8""?>
<ArrayOfContentSearcher xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
  <ContentSearcher>
    <Name>DoNotUseBannedApi</Name>
    <RuleId>BAN1001/Memory/Allocation/_alloca</RuleId>
    <ResourceMatchPattern>\.(c|cpp|cxx)$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>\b(?&lt;refine&gt;_alloca)\s*\(</string>
    </ContentSearchPatterns>
    <FullMatchDetails>'{0}' contains a call to '_alloca', a potentially insecure API that could be replaced with a more secure alternative: '_malloca'.</FullMatchDetails>
    <Severity>2</Severity>
  </ContentSearcher>
  <ContentSearcher>
    <Name>DoNotUseBannedApi</Name>
    <RuleId>BAN1001/String/Input/_getts</RuleId>
    <ResourceMatchPattern>\.(c|cpp|cxx)$</ResourceMatchPattern>
    <ContentSearchPatterns>
      <string>\b(?&lt;refine&gt;_getts)\s*\(</string>
    </ContentSearchPatterns>
    <FullMatchDetails>'{0}' contains a call to '_getts', a potentially insecure API that should be replaced with a more secure alternative: 'gets_s', 'StringCbGets', 'StringCbGetsEx', 'StringCchGets', 'StringCchGetsEx'.</FullMatchDetails>
    <Severity>1</Severity>
  </ContentSearcher>
</ArrayOfContentSearcher>";

            // Arrange
            var mockFileSystem = new Mock<IFileSystem>();
            mockFileSystem.Setup(x => x.FileReadAllText(filePath)).Returns(bannedApiInformation);

            // Act
            SearchDefinitions searchDefinitions = ExportSearchDefinitionsCommand.ExportBannedApi(mockFileSystem.Object, filePath);

            // Assert
            searchDefinitions.Should().NotBeNull();
            searchDefinitions.Definitions.Count.Should().Be(2);
            searchDefinitions.Definitions[1].MatchExpressions.Count(d => d.Level == FailureLevel.Error).Should().Be(1);
            searchDefinitions.Definitions[0].MatchExpressions.Count(d => d.Level == FailureLevel.Warning).Should().Be(1);
        }
    }
}
