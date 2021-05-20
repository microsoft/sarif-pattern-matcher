// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Utilities
{
    internal static class CertificateHelper
    {
        public static ValidationState TryLoadCertificate(string certificatePath,
                                                         ref Fingerprint fingerprint,
                                                         ref string message,
                                                         ref ResultLevelKind resultLevelKind)
        {
            try
            {
                // If this certificate needs a password or it is a bundle, it will throw an exception.
                using var certificate = new X509Certificate2(certificatePath);
                fingerprint = new Fingerprint
                {
                    Thumbprint = certificate.Thumbprint,
                };

                if (!certificate.HasPrivateKey)
                {
                    return ValidationState.NoMatch;
                }

                if (certificate.SubjectName.RawData.Equals(certificate.IssuerName.RawData))
                {
                    resultLevelKind = new ResultLevelKind { Level = FailureLevel.Warning };
                    return ValidationState.Authorized;
                }

                message = "which contains private keys.";
                return ValidationState.Authorized;
            }
            catch (Exception e)
            {
                string fileName = Path.GetFileName(certificatePath);

                if (e is CryptographicException cryptographicException)
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
                }

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

                fingerprint.Thumbprint = string.Join(";", thumbprints);
                message = "which contains private keys.";
                return state;
            }
            catch (Exception e)
            {
                string fileName = Path.GetFileName(certificatePath);
                return ValidatorBase.ReturnUnhandledException(ref message, e, fileName);
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
                fingerprint.Thumbprint = certificate.Thumbprint;

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
            catch (Exception e)
            {
                if (e is CryptographicException cryptographicException)
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
                    fingerprint.Thumbprint = string.Join(";", thumbprints);
                    message = "which contains private keys.";
                }

                return state;
            }
            catch (Exception e)
            {
                return ValidatorBase.ReturnUnhandledException(ref message, e);
            }
        }
    }
}
