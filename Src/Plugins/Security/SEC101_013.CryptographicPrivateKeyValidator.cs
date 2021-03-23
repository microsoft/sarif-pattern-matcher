// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class CryptographicPrivateKeyValidator : ValidatorBase
    {
        internal static CryptographicPrivateKeyValidator Instance;

        static CryptographicPrivateKeyValidator()
        {
            Instance = new CryptographicPrivateKeyValidator();
        }

        public static string IsValidStatic(ref string matchedPattern,
                                           ref Dictionary<string, string> groups,
                                           ref string failureLevel,
                                           ref string fingerprint,
                                           ref string message)
        {
            return ValidatorBase.IsValidStatic(Instance,
                                               ref matchedPattern,
                                               ref groups,
                                               ref failureLevel,
                                               ref fingerprint,
                                               ref message);
        }

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            if (!groups.TryGetNonEmptyValue("key", out string key))
            {
                return nameof(ValidationState.NoMatch);
            }

            groups.TryGetValue("kind", out string kind);
            kind = matchedPattern.Contains(" PGP ") ? "Pgp" : kind;

            key = key.Trim();

            // Attempt to cleanup the key
            if (key.IndexOf('"') > -1)
            {
                string[] linesArray = key.Split(new string[] { Environment.NewLine }, StringSplitOptions.None);
                linesArray = linesArray.Select(x =>
                {
                    return string.Join(string.Empty, x.Replace("\\n", string.Empty)
                                                      .Replace("\"", string.Empty)
                                                      .Where(c => !char.IsWhiteSpace(c)));
                }).ToArray();
                key = string.Join(Environment.NewLine, linesArray);
            }

            fingerprintText = new Fingerprint
            {
                Key = key,
            }.ToString();

            string state = nameof(ValidationState.Unknown);

            switch (kind)
            {
                case "PrivateKeyBlob":
                {
                    byte[] bytes = Convert.FromBase64String(key);

                    // https://docs.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs#private-key-blobs
                    // This offset is the RSAPUBKEY structure. The magic
                    // member must be set to the ASCII encoding of "RSA2".
                    if (bytes[8] != 'R' ||
                        bytes[9] != 'S' ||
                        bytes[10] != 'A' ||
                        bytes[11] != '2')
                    {
                        return nameof(ValidationState.NoMatch);
                    }

                    break;
                }

                case "Pgp":
                {
                    state = GetPrivatePgpKey(key);
                    break;
                }

                case "PemCer":
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(matchedPattern);
                    state = CertificateHelper.TryLoadCertificate(bytes,
                                                                 ref fingerprintText,
                                                                 ref message);
                    break;
                }

                default:
                {
                    string thumbprint = string.Empty;
                    byte[] rawData = Convert.FromBase64String(key);
                    state = CertificateHelper.TryLoadCertificate(rawData,
                                                                 ref thumbprint,
                                                                 ref message);
                    break;
                }
            }

            return state;
        }

        private static string GetPrivatePgpKey(string key)
        {
            using Stream keyIn = new MemoryStream(Encoding.UTF8.GetBytes(key));
            using Stream stream = PgpUtilities.GetDecoderStream(keyIn);
            var secretKeyRingBundle = new PgpSecretKeyRingBundle(stream);

            bool oneOrMorePassphraseProtectedKeys = false;

            foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
            {
                foreach (PgpSecretKey secretKey in kRing.GetSecretKeys())
                {
                    PgpPrivateKey privateKey = null;
                    try
                    {
                        char[] noPassphrase = Array.Empty<char>();
                        privateKey = secretKey.ExtractPrivateKey(noPassphrase);
                    }
                    catch (PgpException)
                    {
                        oneOrMorePassphraseProtectedKeys = true;
                        continue;
                    }

                    return nameof(ValidationState.AuthorizedError);
                }
            }

            if (oneOrMorePassphraseProtectedKeys)
            {
                return nameof(ValidationState.PasswordProtected);
            }

            return nameof(ValidationState.NoMatch);
        }
    }
}
