// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Security.Cryptography;
using System.Text;

using Microsoft.Strings.Interop;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public static class MatchHasher
    {
        private const string HashKey = "7B2FD4B8B55B49428DBFB22C9E61D817";
        private static readonly byte[] HashKeyBytes = Encoding.UTF8.GetBytes(HashKey);

        [ThreadStatic]
        private static SHA256 _sha256;

        private static SHA256 Sha256 => _sha256 ??= SHA256.Create();

        public static string ComputeHash(string matchContent)
        {
            if (string.IsNullOrEmpty(matchContent)) { return string.Empty; }
            byte[] buffer = null;

            // UTF-8 encoded value
            var content8 = String8.Convert(matchContent, ref buffer);

            // With pre-pended salt
            Sha256.TransformBlock(HashKeyBytes, 0, HashKeyBytes.Length, HashKeyBytes, 0);

            Sha256.TransformFinalBlock(content8.Array, content8.Index, content8.Length);

            // Reported as lowercase hex rather than base64
            byte[] hash = Sha256.Hash;
            var text = new StringBuilder(hash.Length / 2);
            foreach (byte b in hash)
            {
                text.Append(b.ToString("x2"));
            }

            return text.ToString();
        }
    }
}
