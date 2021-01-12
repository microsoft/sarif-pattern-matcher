// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Reflection;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class ValidationMethodPair
    {
        public MethodInfo IsValidStatic { get; set; }

        public MethodInfo IsValidDynamic { get; set; }
    }
}
