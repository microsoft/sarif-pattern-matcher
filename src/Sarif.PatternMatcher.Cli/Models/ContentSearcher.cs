// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Xml.Serialization;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli.Models
{
    [XmlRoot(ElementName = "ContentSearcher")]
    public class ContentSearcher
    {
        [XmlElement(ElementName = "Name")]
        public string Name { get; set; }

        [XmlElement(ElementName = "RuleId")]
        public string RuleId { get; set; }

        [XmlElement(ElementName = "ResourceMatchPattern")]
        public string ResourceMatchPattern { get; set; }

        [XmlElement(ElementName = "ContentSearchPatterns")]
        public ContentSearchPatterns ContentSearchPatterns { get; set; }

        [XmlElement(ElementName = "FullMatchDetails")]
        public string FullMatchDetails { get; set; }

        [XmlElement(ElementName = "Severity")]
        public int Severity { get; set; }
    }
}
