// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
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
        /// Alibaba Cloud platform
        /// </summary>
        AlibabaCloud,

        /// <summary>
        /// Azure platform.
        /// </summary>
        Azure,

        /// <summary>
        /// Azure DevOps platform.
        /// </summary>
        AzureDevOps,

        /// <summary>
        /// Aws platform.
        /// </summary>
        Aws,

        /// <summary>
        /// Cloudant platform.
        /// </summary>
        Cloudant,

        /// <summary>
        /// Crates.io platform. https://crates.io/
        /// </summary>
        Crates,

        /// <summary>
        /// Discord platform. https://discord.com/developers
        /// </summary>
        Discord,

        /// <summary>
        /// Dropbox platform. https://www.dropbox.com/developers
        /// </summary>
        Dropbox,

        /// <summary>
        /// Dynatrace platform.
        /// </summary>
        Dynatrace,

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
        /// MailChimp platform.
        /// </summary>
        MailChimp,

        /// <summary>
        /// Mailgun platform.
        /// </summary>
        Mailgun,

        /// <summary>
        /// Npm platform.
        /// </summary>
        Npm,

        /// <summary>
        /// Nuget platform.
        /// </summary>
        NuGet,

        /// <summary>
        /// Office platform.
        /// </summary>
        Office,

        /// <summary>
        /// PayPal platform.
        /// </summary>
        PayPal,

        /// <summary>
        /// Picatic platform.
        /// </summary>
        Picatic,

        /// <summary>
        /// Postman platform.
        /// </summary>
        Postman,

        /// <summary>
        /// SendGrid platform.
        /// </summary>
        SendGrid,

        /// <summary>
        /// Shopify platform.
        /// </summary>
        Shopify,

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

        /// <summary>
        /// Telegram platform.
        /// </summary>
        Telegram,

        /// <summary>
        /// Twilio platform.
        /// </summary>
        Twilio,

        /// <summary>
        /// Xbox platform.
        /// </summary>
        Xbox,
    }
}
