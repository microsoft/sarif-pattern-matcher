// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public static class SecurityExtensions
    {
        public static bool IsBase64EncodedString(this string text)
        {
            try
            {
                Convert.FromBase64String(text);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        public static bool TryGetNonEmptyValue<TKey>(this IDictionary<TKey, FlexMatch> dictionary, TKey key, out FlexMatch value)
        {
            return dictionary.TryGetValue(key, out value) && !string.IsNullOrWhiteSpace(value.Value);
        }

        public static bool TryGetNonEmptyValue<TKey>(this IDictionary<TKey, string> dictionary, TKey key, out string value)
        {
            return dictionary.TryGetValue(key, out value) && !string.IsNullOrWhiteSpace(value);
        }
    }
}
