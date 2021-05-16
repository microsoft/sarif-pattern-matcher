// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    internal class FlexMatchValueComparer : IEqualityComparer<FlexMatch>
    {
        private static FlexMatchValueComparer _instance;

        public static FlexMatchValueComparer Instance
        {
            get
            {
                _instance ??= new FlexMatchValueComparer();
                return _instance;
            }
        }

        public bool Equals(FlexMatch left, FlexMatch right)
        {
            if (ReferenceEquals(left, right))
            {
                return true;
            }

            if (ReferenceEquals(left, null) || ReferenceEquals(right, null))
            {
                return false;
            }

            return left.Value.String == right.Value.String;
        }

        public int GetHashCode(FlexMatch obj)
        {
            if (ReferenceEquals(obj, null))
            {
                return 0;
            }

            return obj.Value.String.GetHashCode();
        }
    }
}
