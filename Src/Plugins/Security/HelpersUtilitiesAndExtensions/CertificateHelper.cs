// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.HelpersUtilitiesAndExtensions
{
    internal static class CertificateHelper
    {
        public static string TryLoadCertificate(string certificatePath,
                                                ref string fingerprintText,
                                                ref string message)
        {
            try
            {
                // If this certificate needs a password or it is a bundle, it will throw an exception.
                using var certificate = new X509Certificate2(certificatePath);
                fingerprintText = certificate.Thumbprint;

                if (!certificate.HasPrivateKey)
                {
                    return nameof(ValidationState.NoMatch);
                }

                message = "which contains private keys.";
                return nameof(ValidationState.Authorized);
            }
            catch (Exception e)
            {
                string fileName = Path.GetFileName(certificatePath);

                if (e is CryptographicException cryptographicException)
                {
                    if (e.Message == "Cannot find the original signer.")
                    {
                        return TryLoadCertificateCollection(certificatePath,
                                                            ref message,
                                                            ref fingerprintText);
                    }

                    if (e.Message == "The specified network password is not correct.")
                    {
                        return nameof(ValidationState.PasswordProtected);
                    }
                }

                ValidatorBase.ReturnUnhandledException(ref message, e, asset: fileName);
                return message;
            }
        }

        public static string TryLoadCertificateCollection(string certificatePath,
                                                          ref string fingerprintText,
                                                          ref string message)
        {
            var certificates = new X509Certificate2Collection();
            try
            {
                // If this certificate needs a password, it will throw an exception.
                certificates.Import(certificatePath);
                var thumbprints = new List<string>();
                string state = nameof(ValidationState.NoMatch);
                foreach (X509Certificate2 certificate in certificates)
                {
                    thumbprints.Add(certificate.Thumbprint);
                    if (certificate.HasPrivateKey)
                    {
                        // Private key detected.
                        state = nameof(ValidationState.Authorized);
                    }
                }

                fingerprintText = string.Join(";", thumbprints);
                message = "which contains private keys.";
                return state;
            }
            catch (Exception e)
            {
                string fileName = Path.GetFileName(certificatePath);
                return ValidatorBase.ReturnUnhandledException(ref message, e, fileName);
            }
        }
    }
}
