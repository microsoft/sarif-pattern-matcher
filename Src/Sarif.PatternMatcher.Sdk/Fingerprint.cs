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
        public const string HostKeyName = "host";
        public const string PartKeyName = "part";
        public const string PathKeyName = "path";
        public const string PortKeyName = "port";
        public const string SchemeKeyName = "scheme";
        public const string SecretKeyName = "secret";
        public const string PlatformKeyName = "platform";
        public const string ResourceKeyName = "resource";
        public const string ThumbprintKeyName = "thumbprint";

        private const char RightBracketReplacement = '\t';
        private const string HashKey = "7B2FD4B8B55B49428DBFB22C9E61D817";

        private const string Base64EncodingSymbolSet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        private static readonly HashSet<string> s_emptyDenyList = new HashSet<string>();
        private static readonly byte[] HashKeyBytes = Encoding.UTF8.GetBytes(HashKey);

        private static readonly HashSet<string> s_assetOnlyKeys =
            new HashSet<string>(new string[]
            {
                PartKeyName,
                PlatformKeyName,
            });

        private static readonly HashSet<string> s_secretKeys =
            new HashSet<string>(new string[]
            {
                SecretKeyName,
            });

        public Fingerprint(string fingerprintText, bool validate = true)
        {
            SecretSymbolSetCount = 0;

            // Validation fingerprint properties.
            Id = Host = Path = Port = Scheme = Secret = Resource = Thumbprint = null;

            // Asset fingerprint properties.
            Platform = Part = null;

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

        public string Host { get; set; }

        public string Part { get; set; }

        public string Path { get; set; }

        public string Port { get; set; }

        public string Scheme { get; set; }

        public string Secret { get; set; }

        public string Resource { get; set; }

        public string Thumbprint { get; set; }

        public string Platform { get; set; }

        /// <summary>
        /// Gets or sets a value that is the count of the valid symbols that
        /// may appear in the fingerprint element that represents an actual
        /// secret, such as a password or key. This value, when present, will
        /// be used to compute the rank of the fingerprint (which is itself
        /// the normalized Shannon entropy of the key or password).
        /// </summary>
        public int SecretSymbolSetCount { get; set; }

        public static bool operator ==(Fingerprint op1, Fingerprint op2)
        {
            return op1.Equals(op2);
        }

        public static bool operator !=(Fingerprint op1, Fingerprint op2)
        {
            return !op1.Equals(op2);
        }

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

            symbolSetCount = SecretSymbolSetCount > 0 ? SecretSymbolSetCount : 128;

            if (!string.IsNullOrEmpty(this.Secret))
            {
                return ShannonEntropy(this.Secret, symbolSetCount) * 100;
            }

            return -1.0;
        }

#pragma warning disable SA1107 // Code should not contain multiple statements on one line

        public void SetProperty(string keyName, string value, bool ignoreRecognizedKeyNames = false)
        {
            switch (keyName)
            {
                case IdKeyName: { Id = value; break; }
                case HostKeyName: { Host = value; break; }
                case PartKeyName: { Part = value; break; }
                case PathKeyName: { Path = value; break; }
                case PortKeyName: { Port = value; break; }
                case SecretKeyName: { Secret = value; break; }
                case SchemeKeyName: { Scheme = value; break; }
                case PlatformKeyName: { Platform = value; break; }
                case ResourceKeyName: { Resource = value; break; }
                case ThumbprintKeyName: { Thumbprint = value; break; }
                default:
                {
                    if (!ignoreRecognizedKeyNames)
                    {
                        throw new ArgumentOutOfRangeException(nameof(keyName));
                    }
                    break;
                }
            }
        }

#pragma warning restore SA1107

        public override string ToString()
        {
            return ToString(this, s_emptyDenyList);
        }

        public override bool Equals(object obj)
        {
            return obj is Fingerprint equatable &&
                Id == equatable.Id &&
                Host == equatable.Host &&
                Part == equatable.Part &&
                Path == equatable.Path &&
                Port == equatable.Port &&
                Scheme == equatable.Scheme &&
                Secret == equatable.Secret &&
                Platform == equatable.Platform &&
                Resource == equatable.Resource &&
                Thumbprint == equatable.Thumbprint;
        }

        public override int GetHashCode()
        {
            int result = 17;
            unchecked
            {
                if (this.Id != null)
                {
                    result = (result * 31) + this.Id.GetHashCode();
                }

                if (this.Host != null)
                {
                    result = (result * 31) + this.Host.GetHashCode();
                }

                if (this.Path != null)
                {
                    result = (result * 31) + this.Path.GetHashCode();
                }

                if (this.Part != null)
                {
                    result = (result * 31) + this.Part.GetHashCode();
                }

                if (this.Platform != null)
                {
                    result = (result * 31) + this.Platform.GetHashCode();
                }

                if (this.Port != null)
                {
                    result = (result * 31) + this.Port.GetHashCode();
                }

                if (this.Scheme != null)
                {
                    result = (result * 31) + this.Scheme.GetHashCode();
                }

                if (this.Secret != null)
                {
                    result = (result * 31) + this.Secret.GetHashCode();
                }

                if (this.Resource != null)
                {
                    result = (result * 31) + this.Resource.GetHashCode();
                }

                if (this.Thumbprint != null)
                {
                    result = (result * 31) + this.Thumbprint.GetHashCode();
                }
            }

            return result;
        }

        internal static string ToString(Fingerprint f, ISet<string> denyList)
        {
            denyList ??= s_emptyDenyList;

            var components = new Dictionary<string, string>(3);

            // These need to remain in alphabetical order.
            if (!string.IsNullOrEmpty(f.Host) && !denyList.Contains(HostKeyName))
            {
                components.Add(HostKeyName, $"[{HostKeyName}={f.Host.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Id) && !denyList.Contains(IdKeyName))
            {
                components.Add(IdKeyName, $"[{IdKeyName}={f.Id.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Part) && !denyList.Contains(PartKeyName))
            {
                components.Add(PartKeyName, $"[{PartKeyName}={f.Part.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Path) && !denyList.Contains(PathKeyName))
            {
                components.Add(PathKeyName, $"[{PathKeyName}={f.Path.Trim()}]");
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

            if (!string.IsNullOrEmpty(f.Scheme) && !denyList.Contains(SchemeKeyName) && !f.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                components.Add(SchemeKeyName, $"[{SchemeKeyName}={f.Scheme.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Secret) && !denyList.Contains(SecretKeyName))
            {
                components.Add(SecretKeyName, $"[{SecretKeyName}={f.Secret.Trim()}]");
            }

            if (!string.IsNullOrEmpty(f.Thumbprint) && !denyList.Contains(ThumbprintKeyName))
            {
                components.Add(ThumbprintKeyName, $"[{ThumbprintKeyName}={f.Thumbprint.Trim()}]");
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
                var text = new StringBuilder(hash.Length / 2);
                foreach (byte b in hash)
                {
                    text.Append(b.ToString("x2"));
                }

                return text.ToString();
            }
        }
    }
}
