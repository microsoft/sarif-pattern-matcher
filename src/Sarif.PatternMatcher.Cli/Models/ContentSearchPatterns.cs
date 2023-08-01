// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Xml.Serialization;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli.Models
{
    [XmlRoot(ElementName = "ContentSearchPatterns")]
    public class ContentSearchPatterns
    {
        [XmlElement(ElementName = "string")]
        public string String { get; set; }
    }
}
