// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public enum AssetPlatform
    {
        /// <summary>
        /// None.
        /// </summary>
        None = 0,

        /// <summary>
        /// Unknown platform.
        /// </summary>
        Unknown = 0,

        /// <summary>
        /// Azure platform.
        /// </summary>
        Azure,

        /// <summary>
        /// Azure DevOps platform.
        /// </summary>
        AzureDevOps,

        /// <summary>
        /// Aws Platform.
        /// </summary>
        Aws,

        /// <summary>
        /// Facebook platform.
        /// </summary>
        Facebook,

        /// <summary>
        /// GitHub platform
        /// </summary>
        GitHub,

        /// <summary>
        /// Google platform.
        /// </summary>
        Google,

        /// <summary>
        /// LinkedIn platform.
        /// </summary>
        LinkedIn,

        /// <summary>
        /// Npm platform.
        /// </summary>
        Npm,

        /// <summary>
        /// Slack platform.
        /// </summary>
        Slack,

        /// <summary>
        /// SqlOnPremise platform.
        /// </summary>
        SqlOnPremise,

        /// <summary>
        /// Square platform.
        /// </summary>
        Square,

        /// <summary>
        /// Stripe platform.
        /// </summary>
        Stripe,
    }
}
