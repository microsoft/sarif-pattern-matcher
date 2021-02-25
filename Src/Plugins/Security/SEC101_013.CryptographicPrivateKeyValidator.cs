// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities;

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
            groups.TryGetValue("key", out string key);
            groups.TryGetValue("kind", out string kind);

            key = key.Trim();

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
                    byte[] magic = new byte[4];

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
    }
}
