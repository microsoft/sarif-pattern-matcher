// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public static class DictionaryExtensions
    {
        public static bool TryGetNonEmptyValue<TKey>(this Dictionary<TKey, FlexMatch> dictionary, TKey key, out FlexMatch value)
        {
            return dictionary.TryGetValue(key, out value) && !string.IsNullOrWhiteSpace(value.Value);
        }

        public static bool TryGetNonEmptyValue<TKey>(this Dictionary<TKey, string> dictionary, TKey key, out string value)
        {
            return dictionary.TryGetValue(key, out value) && !string.IsNullOrWhiteSpace(value);
        }
    }
}
