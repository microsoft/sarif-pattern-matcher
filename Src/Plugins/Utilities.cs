// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public static class Utilities
    {
        public static string CreateReturnValueForException(Exception e)
        {
            return nameof(ValidationState.Unknown) +
                       "#An unexpected exception was caught during validation: " +
                       e.ToString();
        }
    }
}
