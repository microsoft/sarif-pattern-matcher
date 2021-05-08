// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Text.RegularExpressions;

using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public static class PatternMatcherExtensionMethods
    {
        public static Dictionary<string, string> CopyToDictionary(this GroupCollection groups, string[] groupNames)
        {
            var result = new Dictionary<string, string>();

            foreach (string groupName in groupNames)
            {
                result[groupName] = groups[groupName].Value;
            }

            return result;
        }

        public static Dictionary<string, string> CopyToDictionary(this Dictionary<string, FlexMatch> groups)
        {
            var result = new Dictionary<string, string>(groups.Count);

            foreach (KeyValuePair<string, FlexMatch> group in groups)
            {
                result[group.Key] = group.Value.Value;
            }

            return result;
        }
    }
}
