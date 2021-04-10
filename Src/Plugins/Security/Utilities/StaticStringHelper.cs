// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities
{
    public static class StaticStringHelper
    {
        public static bool LikelyPowershellVariable(string input)
        {
            if (input.Length < 4)
            {
                // Not enough space for a variable name in the string
                return false;
            }

            if (input[0] != '$')
            {
                return false;
            }

            if (input[1] != '(')
            {
                return false;
            }

            if (input[input.Length - 1] != ')')
            {
                return false;
            }

            return true;
        }
    }
}
