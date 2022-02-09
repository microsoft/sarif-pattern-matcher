// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.SecurityValidators.Utilities
{
    internal static class CertificateHelper
    {
        public static ValidationState TryLoadCertificate(string certificatePath,
                                                         ref Fingerprint fingerprint,
                                                         ref string message)
        {
            try
            {
                // If this certificate needs a password or it is a bundle, it will throw an exception.
                using var certificate = new X509Certificate2(certificatePath);
                return TryLoadCertificate(certificate, ref fingerprint, ref message);
            }
            catch (Exception e)
            {
                if (e is CryptographicException)
                {
                    if (e.Message == "Cannot find the original signer.")
                    {
                        return TryLoadCertificateCollection(certificatePath,
                                                            ref fingerprint,
                                                            ref message);
                    }

                    if (e.Message == "The specified network password is not correct.")
                    {
                        return ValidationState.PasswordProtected;
                    }

                    if (e.Message.StartsWith("Cannot find the requested object."))
                    {
                        // Garbage data received.
                        return ValidationState.NoMatch;
                    }
                }

                string fileName = Path.GetFileName(certificatePath);
                return ValidatorBase.ReturnUnhandledException(ref message, e, asset: fileName);
            }
        }

        public static ValidationState TryLoadCertificateCollection(string certificatePath,
                                                                   ref Fingerprint fingerprint,
                                                                   ref string message)
        {
            var certificates = new X509Certificate2Collection();
            try
            {
                // If this certificate needs a password, it will throw an exception.
                certificates.Import(certificatePath);
                return TryLoadCertificateCollection(certificates, ref fingerprint, ref message);
            }
            catch (Exception e)
            {
                string fileName = Path.GetFileName(certificatePath);
                return ValidatorBase.ReturnUnhandledException(ref message, e, asset: fileName);
            }
        }

        public static ValidationState TryLoadCertificate(byte[] rawData,
                                                         ref Fingerprint fingerprint,
                                                         ref string message)
        {
            try
            {
                // If this certificate needs a password or it is a bundle, it will throw an exception.
                using var certificate = new X509Certificate2(rawData);
                return TryLoadCertificate(certificate, ref fingerprint, ref message);
            }
            catch (Exception e)
            {
                if (e is CryptographicException)
                {
                    if (e.Message.StartsWith("Cannot find the requested object."))
                    {
                        // Garbage data received.
                        return ValidationState.NoMatch;
                    }

                    if (e.Message.StartsWith("Cannot find the original signer."))
                    {
                        return TryLoadCertificateCollection(rawData,
                                                            ref fingerprint,
                                                            ref message);
                    }

                    if (e.Message == "The specified network password is not correct.")
                    {
                        return ValidationState.PasswordProtected;
                    }
                }

                return ValidatorBase.ReturnUnhandledException(ref message, e);
            }
        }

        public static ValidationState TryLoadCertificateCollection(byte[] rawData,
                                                                   ref Fingerprint fingerprint,
                                                                   ref string message)
        {
            var certificates = new X509Certificate2Collection();
            try
            {
                // If this certificate needs a password, it will throw an exception.
                certificates.Import(rawData);
                return TryLoadCertificateCollection(certificates, ref fingerprint, ref message);
            }
            catch (Exception e)
            {
                return ValidatorBase.ReturnUnhandledException(ref message, e);
            }
        }

        private static ValidationState TryLoadCertificate(X509Certificate2 certificate,
                                                          ref Fingerprint fingerprint,
                                                          ref string message)
        {
            if (fingerprint == default)
            {
                fingerprint = new Fingerprint
                {
                    Thumbprint = certificate.Thumbprint,
                };
            }
            else
            {
                fingerprint.Thumbprint = certificate.Thumbprint;
            }

            if (!certificate.HasPrivateKey)
            {
                return ValidationState.NoMatch;
            }

            if (certificate.SubjectName.RawData.Equals(certificate.IssuerName.RawData))
            {
                return ValidationState.NoMatch;
            }

            message = "which contains private keys.";
            return ValidationState.Authorized;
        }

        private static ValidationState TryLoadCertificateCollection(X509Certificate2Collection certificates,
                                                                    ref Fingerprint fingerprint,
                                                                    ref string message)
        {
            var thumbprints = new List<string>();
            ValidationState state = ValidationState.NoMatch;
            foreach (X509Certificate2 certificate in certificates)
            {
                if (certificate.SubjectName.RawData.Equals(certificate.IssuerName.RawData))
                {
                    continue;
                }

                if (certificate.HasPrivateKey)
                {
                    thumbprints.Add(certificate.Thumbprint);
                    state = ValidationState.Authorized;
                }
            }

            if (thumbprints.Count > 0)
            {
                message = "which contains private keys.";
                string thumbprint = string.Join(";", thumbprints);
                if (fingerprint == default)
                {
                    fingerprint = new Fingerprint
                    {
                        Thumbprint = thumbprint,
                    };
                }
                else
                {
                    fingerprint.Thumbprint = thumbprint;
                }
            }

            return state;
        }
    }
}
