// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    [Flags]
    internal enum FingerprintElements
    {
        None = 0,
        Id = 0x1,
        Host = 0x2,
        Part = 0x4,
        Path = 0x8,
        Port = 0x10,
        Scheme = 0x20,
        Secret = 0x40,
        Platform = 0x80,
        Resource = 0x100,
        Thumbprint = 0x200,
    }
}
