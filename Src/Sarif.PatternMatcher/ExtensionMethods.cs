// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public static class DictionaryExtensions
    {
        public static Dictionary<string, string> ToStringDictionary(this IDictionary<string, FlexMatch> dictionary)
        {
            var stringDictionary = new Dictionary<string, string>();

            foreach (KeyValuePair<string, FlexMatch> kv in dictionary)
            {
                stringDictionary[kv.Key] = kv.Value.Value.String;
            }

            return stringDictionary;
        }

        public static Dictionary<string, FlexMatch> Copy(this IDictionary<string, FlexMatch> dictionary)
        {
            var copy = new Dictionary<string, FlexMatch>();

            foreach (KeyValuePair<string, FlexMatch> kv in dictionary)
            {
                copy[kv.Key] = kv.Value;
            }

            return copy;
        }
    }
}
