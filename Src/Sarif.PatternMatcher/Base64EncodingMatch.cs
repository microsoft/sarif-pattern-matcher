// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class Base64EncodingMatch
    {
        public int MinSourceLength { get; set; }

        public int MaxSourceLength { get; set; }

        public bool IsValid()
        {
            return MinSourceLength > 0 &&
                   MaxSourceLength > 0 &&
                   MinSourceLength <= MaxSourceLength;
        }
    }
}
