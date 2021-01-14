// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public struct Fingerprint
    {
        public const string UriKeyName = "uri";
        public const string HmacKeyName = "hmac";
        public const string HostKeyName = "host";
        public const string AccountKeyName = "acct";
        public const string PasswordKeyName = "pwd";
        public const string KeyNameKeyName = "keyName";
        public const string SasTokenKeyName = "sasToken";
        public const string ThumbprintKeyName = "thumbprint";
        public const string SymmetricKey128BitKeyName = "skey/128";
        public const string SymmetricKey256BitKeyName = "skey/256";
        public const string PersonalAccessTokenGitHubKeyName = "pat/gh";
        public const string PersonalAccessTokenAzureDevOpsKeyName = "pat/ado";

        private const char RightBracketReplacement = '\t';

        public Fingerprint(string fingerprintText)
        {
            Account = Hmac = Host = KeyName = Password = Uri = null;
            PersonalAccessTokenGitHub = PersonalAccessTokenAzureDevOps = null;
            SasToken = SymmetricKey128Bit = SymmetricKey256Bit = Thumbprint = null;

            fingerprintText = fingerprintText ??
                throw new ArgumentNullException(nameof(fingerprintText));

            try
            {
                Parse(fingerprintText);
            }
            catch (Exception e)
            {
                throw new ArgumentException(
                    nameof(fingerprintText),
                    $"'{e.GetType().Name}' exception raised parsing potentially malformed " +
                    $"fingerprint: '{fingerprintText}'. Exception message: '{e.Message}'");
            }

            string computedFingerprint = this.GetFingerprintText();
            if (!computedFingerprint.Equals(fingerprintText))
            {
                throw new ArgumentException(
                    nameof(fingerprintText),
                    $"Fingerprint did not round-trip. Ensure properties are in sorted order, that " +
                    $"there are no spaces between components, etc. Initializer was '{fingerprintText}'. " +
                    $"Valid computed fingerprint was '{computedFingerprint}'.");
            }
        }

        private enum ParseState
        {
            GatherKeyOpen = 0,
            GatherKeyName,
            GatherValue,
        }

        public string Uri { get; internal set; }

        public string Hmac { get; internal set; }

        public string Host { get; internal set; }

        public string Account { get; internal set; }

        public string KeyName { get; internal set; }


        public string Password { get; internal set; }

        public string SasToken { get; internal set; }

        public string Thumbprint { get; internal set; }

        public string SymmetricKey128Bit { get; internal set; }

        public string SymmetricKey256Bit { get; internal set; }

        public string PersonalAccessTokenGitHub { get; internal set; }

        public string PersonalAccessTokenAzureDevOps { get; internal set; }

        public string GetFingerprintText() => this.ToString();

#pragma warning disable SA1107 // Code should not contain multiple statements on one line
        public void SetProperty(string keyName, string value)
        {
            switch (keyName)
            {
                case UriKeyName: { Uri = value; break; }
                case HmacKeyName: { Hmac = value; break; }
                case HostKeyName: { Host = value; break; }
                case AccountKeyName: { Account = value; break; }
                case KeyNameKeyName: { KeyName = value; break; }
                case PasswordKeyName: { Password = value; break; }
                case SasTokenKeyName: { SasToken = value; break; }
                case ThumbprintKeyName: { Thumbprint = value; break; }
                case SymmetricKey128BitKeyName: { SymmetricKey128Bit = value; break; }
                case SymmetricKey256BitKeyName: { SymmetricKey256Bit = value; break; }
                case PersonalAccessTokenGitHubKeyName: { PersonalAccessTokenGitHub = value; break; }
                case PersonalAccessTokenAzureDevOpsKeyName: { PersonalAccessTokenAzureDevOps = value; break; }
                default: throw new ArgumentException(nameof(keyName));
            }
        }
#pragma warning restore SA1107

        public override string ToString()
        {
            var components = new List<string>(3);

            // These need to remain in alphabetical order.
            if (Account != null)
            {
                components.Add($"[{AccountKeyName}={this.Account}]");
            }

            if (Hmac != null)
            {
                components.Add($"[{HmacKeyName}={this.Hmac}]");
            }

            if (Host != null)
            {
                components.Add($"[{HostKeyName}={this.Host}]");
            }

            if (KeyName != null)
            {
                components.Add($"[{KeyNameKeyName}={this.KeyName}]");
            }

            if (Password != null)
            {
                components.Add($"[{PasswordKeyName}={this.Password}]");
            }

            if (PersonalAccessTokenAzureDevOps != null)
            {
                components.Add($"[{PersonalAccessTokenAzureDevOpsKeyName}={this.PersonalAccessTokenAzureDevOps}]");
            }

            if (PersonalAccessTokenGitHub != null)
            {
                components.Add($"[{PersonalAccessTokenGitHubKeyName}={this.PersonalAccessTokenGitHub}]");
            }

            if (SasToken != null)
            {
                components.Add($"[{SasTokenKeyName}={this.SasToken}]");
            }

            if (SymmetricKey128Bit != null)
            {
                components.Add($"[{SymmetricKey128BitKeyName}={this.SymmetricKey128Bit}]");
            }

            if (SymmetricKey256Bit != null)
            {
                components.Add($"[{SymmetricKey256BitKeyName}={this.SymmetricKey256Bit}]");
            }

            if (Thumbprint != null)
            {
                components.Add($"[{ThumbprintKeyName}={this.Thumbprint}]");
            }

            if (Uri != null)
            {
                components.Add($"[{UriKeyName}={this.Uri}]");
            }

            return components.Count > 0 ?
                string.Concat(components) :
                string.Empty;
        }

        internal void Parse(string fingerprintText)
        {
            ParseState parseState = ParseState.GatherKeyOpen;
            string currentKey = null;

            var sortedKeys = new SortedList<string, string>();

            for (int i = 0; i < fingerprintText.Length; i++)
            {
                switch (parseState)
                {
                    case ParseState.GatherKeyOpen:
                    {
                        while (fingerprintText[i] != '[') { i++; }
                        parseState = ParseState.GatherKeyName;
                        break;
                    }

                    case ParseState.GatherKeyName:
                    {
                        int keyNameStart = i;
                        while (fingerprintText[i] != '=') { i++; }
                        currentKey = fingerprintText.Substring(keyNameStart, i - keyNameStart);

                        if (sortedKeys.ContainsKey(currentKey))
                        {
                            throw new ArgumentException($"The '{currentKey}' key name is duplicated in the fingerprint.");
                        }

                        sortedKeys.Add(currentKey, currentKey);

                        parseState = ParseState.GatherValue;
                        break;
                    }

                    case ParseState.GatherValue:
                    {
                        int valueStart = i;
                        while (fingerprintText[i] != ']') { i++; }
                        string value = fingerprintText.Substring(valueStart, i - valueStart);
                        parseState = ParseState.GatherKeyOpen;
                        SetProperty(currentKey, value);
                        break;
                    }
                }
            }
        }
    }
}
