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

        public static IEnumerable<ValidationResult> IsValidStatic(ref string matchedPattern,
                                                                  ref Dictionary<string, string> groups,
                                                                  ref string message)
        {
            return IsValidStatic(Instance,
                                 ref matchedPattern,
                                 ref groups,
                                 ref message);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(ref string matchedPattern,
                                                                             ref Dictionary<string, string> groups,
                                                                             ref string message)
        {
            if (!groups.TryGetNonEmptyValue("secret", out string secret))
            {
                return ValidationResult.NoMatch;
            }

            groups.TryGetValue("kind", out string kind);
            kind = matchedPattern.Contains(" PGP ") ? "Pgp" : kind;

            secret = secret.Trim();

            // Attempt to cleanup the secret
            if (secret.IndexOf('"') > -1)
            {
                string[] linesArray = secret.Split(new string[] { Environment.NewLine }, StringSplitOptions.None);
                linesArray = linesArray.Select(x => string.Join(string.Empty, x.Replace("\\n", string.Empty)
                                                      .Replace("\"", string.Empty)
                                                      .Where(c => !char.IsWhiteSpace(c)))).ToArray();
                secret = string.Join(Environment.NewLine, linesArray);
            }

            var fingerprint = new Fingerprint
            {
                Secret = secret,
            };

            ValidationState state = ValidationState.Unknown;

            switch (kind)
            {
                case "PrivateKeyBlob":
                {
                    byte[] bytes = Convert.FromBase64String(secret);

                    // https://docs.microsoft.com/en-us/windows/win32/seccrypto/base-provider-secret-blobs#private-secret-blobs
                    // This offset is the RSAPUBKEY structure. The magic
                    // member must be set to the ASCII encoding of "RSA2".
                    if (bytes[8] != 'R' ||
                        bytes[9] != 'S' ||
                        bytes[10] != 'A' ||
                        bytes[11] != '2')
                    {
                        return ValidationResult.NoMatch;
                    }

                    break;
                }

                case "Pgp":
                {
                    state = GetPrivatePgpKey(secret);
                    break;
                }

                case "PemCer":
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(matchedPattern);
                    state = CertificateHelper.TryLoadCertificate(bytes,
                                                                 ref fingerprint,
                                                                 ref message);
                    break;
                }

                default:
                {
                    string thumbprint = string.Empty;
                    try
                    {
                        byte[] rawData = Convert.FromBase64String(secret);
                        state = CertificateHelper.TryLoadCertificate(rawData,
                                                                     ref fingerprint,
                                                                     ref message);
                    }
                    catch (FormatException)
                    {
                        return ValidationResult.NoMatch;
                    }

                    break;
                }
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = fingerprint,
                ValidationState = state,
            };

            return new[] { validationResult };
        }

        private static ValidationState GetPrivatePgpKey(string secret)
        {
            using Stream keyIn = new MemoryStream(Encoding.UTF8.GetBytes(secret));
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

                    return ValidationState.Authorized;
                }
            }

            if (oneOrMorePassphraseProtectedKeys)
            {
                return ValidationState.PasswordProtected;
            }

            return ValidationState.NoMatch;
        }
    }
}
