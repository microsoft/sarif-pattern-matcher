// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

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
    }
}
