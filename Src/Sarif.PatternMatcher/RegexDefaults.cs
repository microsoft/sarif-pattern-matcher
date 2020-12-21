// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System.Text.RegularExpressions;

namespace Sarif.PatternMatcher
{
    public static class RegexDefaults
    {
        public const RegexOptions DefaultOptionsCaseInsensitive = RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture | RegexOptions.IgnoreCase;
        public const RegexOptions DefaultOptionsCaseSensitive = RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture;
    }
}
