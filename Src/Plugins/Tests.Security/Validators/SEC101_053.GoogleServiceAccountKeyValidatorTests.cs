// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using FluentAssertions;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class GoogleServiceAccountKeyValidatorTests : GoogleServiceAccountKeyValidator
    {
        // [Fact] TODO: Complete test https://github.com/microsoft/sarif-pattern-matcher/issues/277
        public void DynamicValidation_Test()
        {
            string fingerprintText = string.Format("[acct={0}][key={1}]", "test0", "test1");
            string message = null;
            IsValidDynamicHelper(ref fingerprintText, ref message);
        }
    }
}
