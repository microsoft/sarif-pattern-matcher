// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    [AttributeUsage(AttributeTargets.Class, Inherited = false)]
    public class RuleDescriptorAttribute : Attribute
    {
        public RuleDescriptorAttribute(string id)
        {
            Id = id;
        }

        public string Id { get; set; }
    }
}
