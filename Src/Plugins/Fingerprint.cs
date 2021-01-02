// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins
{
    public class Fingerprint
    {
        public string Host { get; set; }

        public string Account { get; set; }

        public string Resource { get; set; }

        public string Password { get; set; }

        public string Key { get; set; }

        public string Id { get; set; }

        public string GetFingerPrint() => this.ToString();

        public override string ToString()
        {
            if (Host == null && Account == null && Resource == null && Password == null)
            {
                return string.Empty;
            }

            var components = new List<string>(4);

            if (Id != null) { components.Add($"i:{Host}"); }
            if (Key != null) { components.Add($"k:{Host}"); }
            if (Host != null) { components.Add($"h:{Host}"); }
            if (Account != null) { components.Add($"a:{Account}"); }
            if (Resource != null) { components.Add($"r:{Resource}"); }
            if (Password != null) { components.Add($"p:{Password}"); }

            return string.Join("#", components);
        }
    }
}
