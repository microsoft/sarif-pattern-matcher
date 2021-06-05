// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;
using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

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

        public static IEnumerable<ValidationResult> IsValidStatic(Dictionary<string, FlexMatch> groups)
        {
            return IsValidStatic(Instance, groups);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(Dictionary<string, FlexMatch> groups)
        {
            if (!groups.TryGetNonEmptyValue("secret", out FlexMatch secret))
            {
                return ValidationResult.CreateNoMatch();
            }

            string matchedPattern = groups["0"].Value;

            groups.TryGetValue("kind", out FlexMatch kind);
            string kindValue = matchedPattern.Contains(" PGP ") ? "Pgp" : kind?.Value.String;

            string secretValue = secret.Value.String.Trim();

            // Attempt to cleanup the secret
            if (secretValue.IndexOf('"') > -1 || secretValue.IndexOf("\\n") > -1)
            {
                string[] linesArray = secret.Value.String.Split(new string[] { Environment.NewLine }, StringSplitOptions.None);
                linesArray = linesArray.Select(x => string.Join(string.Empty, x.Replace("\\n", string.Empty)
                                                      .Replace("\"", string.Empty)
                                                      .Where(c => !char.IsWhiteSpace(c)))).ToArray();
                secretValue = string.Join(Environment.NewLine, linesArray);
            }

            var fingerprint = new Fingerprint
            {
                Secret = secretValue,
            };

            ValidationState state = ValidationState.Unknown;
            string message = string.Empty;

            switch (kindValue)
            {
                case "PrivateKeyBlob":
                {
                    try
                    {
                        byte[] bytes = Convert.FromBase64String(secret.Value);

                        // https://docs.microsoft.com/en-us/windows/win32/seccrypto/base-provider-secret-blobs#private-secret-blobs
                        // This offset is the RSAPUBKEY structure. The magic
                        // member must be set to the ASCII encoding of "RSA2".
                        if (bytes[8] != 'R' ||
                            bytes[9] != 'S' ||
                            bytes[10] != 'A' ||
                            bytes[11] != '2')
                        {
                            return ValidationResult.CreateNoMatch();
                        }
                    }
                    catch (FormatException)
                    {
                        return ValidationResult.CreateNoMatch();
                    }

                    break;
                }

                case "Pgp":
                {
                    state = GetPrivatePgpKey(secretValue);
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
                        byte[] rawData = Convert.FromBase64String(secretValue);
                        state = CertificateHelper.TryLoadCertificate(rawData,
                                                                     ref fingerprint,
                                                                     ref message);
                    }
                    catch (FormatException)
                    {
                        return ValidationResult.CreateNoMatch();
                    }

                    break;
                }
            }

            var validationResult = new ValidationResult
            {
                Message = message,
                ValidationState = state,
                RegionFlexMatch = secret,
                Fingerprint = fingerprint,
            };

            return new[] { validationResult };
        }

        private static ValidationState GetPrivatePgpKey(string secret)
        {
            try
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
            catch (IOException ex)
            {
                if (ex.Message == "unknown object in stream Reserved")
                {
                    return ValidationState.NoMatch;
                }

                throw;
            }
        }
    }
}
