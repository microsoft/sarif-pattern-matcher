// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli.Enums
{
    public enum ConnectionType
    {
        /// <summary>
        /// Kusto database.
        /// </summary>
        Kusto = 0,

        /// <summary>
        /// SqlLite database.
        /// </summary>
        SqlLite,
    }
}
