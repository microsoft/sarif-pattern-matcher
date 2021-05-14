// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public static class ExtensionMethods
    {
        public static string Truncate(this string text, int lengthExclusiveOfEllipsis = 6)
        {
            text ??= string.Empty;

            if (text.Length <= lengthExclusiveOfEllipsis)
            {
                return text;
            }

            // "\u2026" == "…"
            return text.Substring(0, lengthExclusiveOfEllipsis) + "\u2026";
        }
    }
}
