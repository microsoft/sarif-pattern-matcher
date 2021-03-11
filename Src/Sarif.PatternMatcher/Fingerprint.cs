// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public struct Fingerprint
    {
        public const string IdKeyName = "id";
        public const string KeyKeyName = "key";
        public const string UriKeyName = "uri";
        public const string HmacKeyName = "hmac";
        public const string HostKeyName = "host";
        public const string PortKeyName = "port";
        public const string AccountKeyName = "acct";
        public const string PasswordKeyName = "pwd";
        public const string KeyNameKeyName = "keyName";
        public const string PlatformKeyName = "platform";
        public const string ResourceKeyName = "resource";
        public const string SasTokenKeyName = "sasToken";
        public const string ThumbprintKeyName = "thumbprint";
        public const string PersonalAccessTokenKeyName = "pat";
        public const string SymmetricKey128BitKeyName = "skey/128";
        public const string SymmetricKey256BitKeyName = "skey/256";

        private const char RightBracketReplacement = '\t';
        private static readonly HashSet<string> s_emptyDenyList = new HashSet<string>();

        private static readonly HashSet<string> s_assetOnlyKeys =
            new HashSet<string>(new string[]
            {
                PlatformKeyName,
            });

        private static readonly HashSet<string> s_secretKeys =
            new HashSet<string>(new string[]
            {
                KeyKeyName,
                HmacKeyName,
                PasswordKeyName,
                SasTokenKeyName,
                PersonalAccessTokenKeyName,
                SymmetricKey128BitKeyName,
                SymmetricKey256BitKeyName,
            });

        public Fingerprint(string fingerprintText)
        {
            Account = Hmac = Host = Port = Id = Key = KeyName = Password = Uri = Platform = Resource = null;
            SasToken = PersonalAccessToken = SymmetricKey128Bit = SymmetricKey256Bit = Thumbprint = null;

            fingerprintText = fingerprintText ??
                throw new ArgumentNullException(nameof(fingerprintText));

            try
            {
                Parse(fingerprintText);
            }
            catch (Exception e)
            {
                throw new ArgumentException(
                    $"'{e.GetType().Name}' exception raised parsing potentially malformed " +
                    $"fingerprint: '{fingerprintText}'. Exception message: '{e.Message}'",
                    nameof(fingerprintText));
            }

            string computedFingerprint = this.GetComprehensiveFingerprintText();
            if (!computedFingerprint.Equals(fingerprintText))
            {
                throw new ArgumentException(
                    $"Fingerprint did not round-trip. Ensure properties are in sorted order, that " +
                    $"there are no spaces between components, etc. Initializer was '{fingerprintText}'. " +
                    $"Valid computed fingerprint was '{computedFingerprint}'.",
                    nameof(fingerprintText));
            }
        }

        private enum ParseState
        {
            GatherKeyOpen = 0,
            GatherKeyName,
            GatherValue,
        }

        public string Id { get; set; }

        public string Key { get; set; }

        public string Uri { get; set; }

        public string Hmac { get; set; }

        public string Host { get; set; }

        public string Port { get; set; }

        public string Account { get; set; }

        public string KeyName { get; set; }

        public string Password { get; set; }

        public string SasToken { get; set; }

        public string Platform { get; set; }

        public string Resource { get; set; }

        public string Thumbprint { get; set; }

        public string SymmetricKey128Bit { get; set; }

        public string SymmetricKey256Bit { get; set; }

        public string PersonalAccessToken { get; set; }

        public string GetComprehensiveFingerprintText() => ToString(this, denyList: s_emptyDenyList);

        public string GetAssetFingerprintText() => ToString(this, denyList: s_secretKeys);

        public string GetValidationFingerprintText() => ToString(this, denyList: s_assetOnlyKeys);

#pragma warning disable SA1107 // Code should not contain multiple statements on one line
        public void SetProperty(string keyName, string value)
        {
            switch (keyName)
            {
                case IdKeyName: { Id = value; break; }
                case KeyKeyName: { Key = value; break; }
                case UriKeyName: { Uri = value; break; }
                case HmacKeyName: { Hmac = value; break; }
                case HostKeyName: { Host = value; break; }
                case PortKeyName: { Port = value; break; }
                case AccountKeyName: { Account = value; break; }
                case KeyNameKeyName: { KeyName = value; break; }
                case PasswordKeyName: { Password = value; break; }
                case SasTokenKeyName: { SasToken = value; break; }
                case PlatformKeyName: { Platform = value; break; }
                case ResourceKeyName: { Resource = value; break; }
                case ThumbprintKeyName: { Thumbprint = value; break; }
                case SymmetricKey128BitKeyName: { SymmetricKey128Bit = value; break; }
                case SymmetricKey256BitKeyName: { SymmetricKey256Bit = value; break; }
                case PersonalAccessTokenKeyName: { PersonalAccessToken = value; break; }
                default: throw new ArgumentOutOfRangeException(nameof(keyName));
            }
        }
#pragma warning restore SA1107

        public override string ToString()
        {
            return ToString(this, s_emptyDenyList);
        }

        internal static string ToString(Fingerprint f, ISet<string> denyList)
        {
            denyList ??= s_emptyDenyList;

            var components = new List<string>(3);

            // These need to remain in alphabetical order.
            if (!string.IsNullOrEmpty(f.Account) && !denyList.Contains(AccountKeyName))
            {
                components.Add($"[{AccountKeyName}={f.Account.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Hmac) && !denyList.Contains(HmacKeyName))
            {
                components.Add($"[{HmacKeyName}={f.Hmac.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Host) && !denyList.Contains(HostKeyName))
            {
                components.Add($"[{HostKeyName}={f.Host.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Id) && !denyList.Contains(IdKeyName))
            {
                components.Add($"[{IdKeyName}={f.Id.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Key) && !denyList.Contains(KeyKeyName))
            {
                components.Add($"[{KeyKeyName}={f.Key.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.KeyName) && !denyList.Contains(KeyNameKeyName))
            {
                components.Add($"[{KeyNameKeyName}={f.KeyName.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Password) && !denyList.Contains(PasswordKeyName))
            {
                components.Add($"[{PasswordKeyName}={f.Password.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.PersonalAccessToken) && !denyList.Contains(PersonalAccessTokenKeyName))
            {
                components.Add($"[{PersonalAccessTokenKeyName}={f.PersonalAccessToken.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Platform) && !denyList.Contains(PlatformKeyName))
            {
                components.Add($"[{PlatformKeyName}={f.Platform.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Port) && !denyList.Contains(PortKeyName))
            {
                components.Add($"[{PortKeyName}={f.Port.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Resource) && !denyList.Contains(ResourceKeyName))
            {
                components.Add($"[{ResourceKeyName}={f.Resource.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.SasToken) && !denyList.Contains(SasTokenKeyName))
            {
                components.Add($"[{SasTokenKeyName}={f.SasToken.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.SymmetricKey128Bit) && !denyList.Contains(SymmetricKey128BitKeyName))
            {
                components.Add($"[{SymmetricKey128BitKeyName}={f.SymmetricKey128Bit.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.SymmetricKey256Bit) && !denyList.Contains(SymmetricKey256BitKeyName))
            {
                components.Add($"[{SymmetricKey256BitKeyName}={f.SymmetricKey256Bit.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Thumbprint) && !denyList.Contains(ThumbprintKeyName))
            {
                components.Add($"[{ThumbprintKeyName}={f.Thumbprint.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Uri) && !denyList.Contains(UriKeyName))
            {
                components.Add($"[{UriKeyName}={f.Uri.Trim()}]");
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
