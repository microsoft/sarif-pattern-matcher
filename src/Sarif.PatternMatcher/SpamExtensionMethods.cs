// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public static class SpamExtensionMethods
    {
        public static Dictionary<string, string> ToStringDictionary(this IDictionary<string, FlexMatch> dictionary)
        {
            var stringDictionary = new Dictionary<string, string>(dictionary.Count);

            foreach (KeyValuePair<string, FlexMatch> kv in dictionary)
            {
                stringDictionary[kv.Key] = kv.Value.Value.String;
            }

            return stringDictionary;
        }

        public static Dictionary<string, FlexMatch> Copy(this IDictionary<string, FlexMatch> dictionary)
        {
            return new Dictionary<string, FlexMatch>(dictionary);
        }

        public static void AddProperties(this IDictionary<string, FlexMatch> dictionary, IDictionary<string, string> properties)
        {
            if (properties == null || properties.Count == 0)
            {
                return;
            }

            foreach (KeyValuePair<string, string> kv in properties)
            {
                if (!dictionary.ContainsKey(kv.Key))
                {
                    dictionary[kv.Key] = new FlexMatch() { Value = kv.Value };
                }
            }
        }
    }
}
