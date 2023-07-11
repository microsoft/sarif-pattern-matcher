// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Xml.Serialization;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli.Models
{
    [XmlRoot(ElementName = "ArrayOfContentSearcher")]
    public class ArrayOfContentSearcher
    {
        [XmlElement(ElementName = "ContentSearcher")]
        public List<ContentSearcher> ContentSearcher { get; set; }
    }
}
