// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public enum RegexEngine
    {
        None,
        DotNet,
        CachedDotNet,
        RE2,
        IronRE2,
    }
}
