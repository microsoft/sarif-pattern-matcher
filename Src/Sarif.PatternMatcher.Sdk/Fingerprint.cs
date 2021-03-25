// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Strings.Interop;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
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
        private const string HashKey = "7B2FD4B8B55B49428DBFB22C9E61D817";
        private const string Base64EncodingSymbolSet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        private static readonly HashSet<string> s_emptyDenyList = new HashSet<string>();
        private static readonly byte[] HashKeyBytes = Encoding.UTF8.GetBytes(HashKey);

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

        /// <summary>
        /// Normalized specific Shannon entropy. See https://rosettacode.org/wiki/Entropy.
        /// </summary>
        /// <param name="input">Input string to be analyzed.</param>
        /// <param name="countOfPossibleSymbols">Count of possible symbols.</param>
        /// <returns>A normalized specific Shannon entropy level for the input string.</returns>
        public static double ShannonEntropy(string input, int countOfPossibleSymbols)
        {
            double entropy = 0;

            if (string.IsNullOrWhiteSpace(input)) { return entropy; }

            var charCounts = new Dictionary<char, double>();

            foreach (char ch in input)
            {
                charCounts.TryGetValue(ch, out double count);
                charCounts[ch] = ++count;
            }

            foreach (char ch in charCounts.Keys)
            {
                double count = charCounts[ch];
                double frequency = count / input.Length;
                entropy += -(frequency * Math.Log(frequency, countOfPossibleSymbols));
            }

            return entropy;
        }

        public Fingerprint(string fingerprintText, bool validate = true)
        {
            SecretSymbolSetCount = 0;

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

            if (validate)
            {
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

        /// <summary>
        /// Gets or sets a value that is the count of the valid symbols that
        /// may appear in the fingerprint element that represents an actual
        /// secret, such as a password or key. This value, when present, will
        /// be used to compute the rank of the fingerprint (which is itself
        /// the normalized Shannon entropy of the key or password).
        /// </summary>
        public int SecretSymbolSetCount { get; set; }

        public string GetComprehensiveFingerprintText() => ToString(this, denyList: s_emptyDenyList);

        public string GetAssetFingerprintText() => ToString(this, denyList: s_secretKeys);

        public string GetValidationFingerprintText() => ToString(this, denyList: s_assetOnlyKeys);

        public string GetValidationFingerprintHashText()
        {
            string validationFingerprint = ToString(this, denyList: s_assetOnlyKeys);
            return ComputeHash(validationFingerprint);
        }

        /// <summary>
        /// A ranking of the validity of this fingerprint, as measured solely by the
        /// normalized shannon entropy of the elements of the fingerprint that comprise
        /// the password or key (where we can expect a high degree of entropy for an
        /// actual, randomly generated value).
        /// </summary>
        /// <returns>
        /// The normalized Shannon entropy of the fingerprint secret, expressed
        /// as value from 0.0 to 100.0, inclusive. A value of -1.0 indicates that
        /// no meaningful rank value could be generated.
        /// </returns>
        public double GetRank()
        {
            int symbolSetCount = Base64EncodingSymbolSet.Length;

            if (!string.IsNullOrEmpty(this.SymmetricKey128Bit))
            {
                return ShannonEntropy(this.SymmetricKey128Bit, symbolSetCount) * 100;
            }

            if (!string.IsNullOrEmpty(this.SymmetricKey256Bit))
            {
                return ShannonEntropy(this.SymmetricKey256Bit, symbolSetCount) * 100;
            }

            symbolSetCount = SecretSymbolSetCount > 0 ? SecretSymbolSetCount : 128;

            if (!string.IsNullOrEmpty(this.Key))
            {
                return ShannonEntropy(this.Key, symbolSetCount) * 100;
            }

            if (!string.IsNullOrEmpty(this.Hmac))
            {
                return ShannonEntropy(this.Hmac, symbolSetCount) * 100;
            }

            if (!string.IsNullOrEmpty(this.Password))
            {
                return ShannonEntropy(this.Password, symbolSetCount) * 100;
            }

            if (!string.IsNullOrEmpty(this.PersonalAccessToken))
            {
                return ShannonEntropy(this.PersonalAccessToken, symbolSetCount) * 100;
            }

            return -1.0;
        }

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

            var components = new Dictionary<string, string>(3);

            // These need to remain in alphabetical order.
            if (!string.IsNullOrEmpty(f.Account) && !denyList.Contains(AccountKeyName))
            {
                components.Add(AccountKeyName, $"[{AccountKeyName}={f.Account.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Hmac) && !denyList.Contains(HmacKeyName))
            {
                components.Add(HmacKeyName, $"[{HmacKeyName}={f.Hmac.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Host) && !denyList.Contains(HostKeyName))
            {
                components.Add(HostKeyName, $"[{HostKeyName}={f.Host.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Id) && !denyList.Contains(IdKeyName))
            {
                components.Add(IdKeyName, $"[{IdKeyName}={f.Id.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Key) && !denyList.Contains(KeyKeyName))
            {
                components.Add(KeyKeyName, $"[{KeyKeyName}={f.Key.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.KeyName) && !denyList.Contains(KeyNameKeyName))
            {
                components.Add(KeyNameKeyName, $"[{KeyNameKeyName}={f.KeyName.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Password) && !denyList.Contains(PasswordKeyName))
            {
                components.Add(PasswordKeyName, $"[{PasswordKeyName}={f.Password.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.PersonalAccessToken) && !denyList.Contains(PersonalAccessTokenKeyName))
            {
                components.Add(PersonalAccessTokenKeyName, $"[{PersonalAccessTokenKeyName}={f.PersonalAccessToken.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Platform) && !denyList.Contains(PlatformKeyName))
            {
                components.Add(PlatformKeyName, $"[{PlatformKeyName}={f.Platform.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Port) && !denyList.Contains(PortKeyName))
            {
                components.Add(PortKeyName, $"[{PortKeyName}={f.Port.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Resource) && !denyList.Contains(ResourceKeyName))
            {
                components.Add(ResourceKeyName, $"[{ResourceKeyName}={f.Resource.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.SasToken) && !denyList.Contains(SasTokenKeyName))
            {
                components.Add(SasTokenKeyName, $"[{SasTokenKeyName}={f.SasToken.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.SymmetricKey128Bit) && !denyList.Contains(SymmetricKey128BitKeyName))
            {
                components.Add(SymmetricKey128BitKeyName, $"[{SymmetricKey128BitKeyName}={f.SymmetricKey128Bit.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.SymmetricKey256Bit) && !denyList.Contains(SymmetricKey256BitKeyName))
            {
                components.Add(SymmetricKey256BitKeyName, $"[{SymmetricKey256BitKeyName}={f.SymmetricKey256Bit.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Thumbprint) && !denyList.Contains(ThumbprintKeyName))
            {
                components.Add(ThumbprintKeyName, $"[{ThumbprintKeyName}={f.Thumbprint.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Uri) && !denyList.Contains(UriKeyName))
            {
                components.Add(UriKeyName, $"[{UriKeyName}={f.Uri.Trim()}]");
            }

            return components.Count > 0 ?
                string.Concat(components.Where(c => !string.IsNullOrEmpty(c.Value)).OrderBy(c => c.Key).Select(v => v.Value)) :
                string.Empty;
        }

        internal void Parse(string fingerprintText)
        {
            ParseState parseState = ParseState.GatherKeyOpen;
            string currentKey = null;

            var keys = new HashSet<string>();

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

                        if (keys.Contains(currentKey))
                        {
                            throw new ArgumentException($"The '{currentKey}' key name is duplicated in the fingerprint.");
                        }

                        keys.Add(currentKey);

                        parseState = ParseState.GatherValue;
                        break;
                    }

                    case ParseState.GatherValue:
                    {
                        int valueStart = i;
                        while (fingerprintText[i] != ']' || (i + 1 < fingerprintText.Length && fingerprintText[i + 1] != '[')) { i++; }
                        string value = fingerprintText.Substring(valueStart, i - valueStart);
                        parseState = ParseState.GatherKeyOpen;
                        SetProperty(currentKey, value);
                        break;
                    }
                }
            }
        }

        private static string ComputeHash(string matchContent)
        {
            if (string.IsNullOrEmpty(matchContent)) { return string.Empty; }
            byte[] buffer = null;

            using (SHA256 hasher = SHA256Managed.Create())
            {
                // UTF-8 encoded value
                var content8 = String8.Convert(matchContent, ref buffer);

                // With pre-pended salt
                hasher.TransformBlock(HashKeyBytes, 0, HashKeyBytes.Length, HashKeyBytes, 0);

                hasher.TransformFinalBlock(content8.Array, content8.Index, content8.Length);

                // Reported as lowercase hex rather than base64
                byte[] hash = hasher.Hash;
                StringBuilder text = new StringBuilder(hash.Length / 2);
                foreach (byte b in hash)
                {
                    text.Append(b.ToString("x2"));
                }

                return text.ToString();
            }
        }
    }
}
