// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class Base64EncodingMatch
    {
        public int MinMatchLength { get; set; }

        public int MaxMatchLength { get; set; }

        public bool IsValid()
        {
            return MinMatchLength > 0 &&
                   MaxMatchLength > 0 &&
                   MinMatchLength <= MaxMatchLength;
        }
    }
}
