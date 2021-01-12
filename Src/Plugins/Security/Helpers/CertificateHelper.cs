// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers
{
    internal static class CertificateHelper
    {
        public static string TryLoadCertificate(string certificatePath, ref string thumbprint)
        {
            X509Certificate2 certificate = null;
            try
            {
                // If this certificate needs a password or it is a bundle, it will throw an exception.
                certificate = new X509Certificate2(certificatePath);
                thumbprint = certificate.Thumbprint;
                return certificate.HasPrivateKey
                    ? nameof(ValidationState.Authorized)
                    : nameof(ValidationState.NoMatch);
            }
            catch (CryptographicException e)
            {
                return e.Message switch
                {
                    "Cannot find the original signer." => TryLoadCertificateCollection(certificatePath, ref thumbprint),
                    _ => ValidatorBase.CreateReturnValueForUnknownException(e, Path.GetFileName(certificatePath)),
                };
            }
            catch (Exception e)
            {
                return ValidatorBase.CreateReturnValueForUnknownException(e, Path.GetFileName(certificatePath));
            }
            finally
            {
                certificate?.Dispose();
            }
        }

        public static string TryLoadCertificateCollection(string certificatePath, ref string thumbprint)
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

                thumbprint = string.Join(";", thumbprints);
                return state;
            }
            catch (Exception e)
            {
                return ValidatorBase.CreateReturnValueForUnknownException(e, Path.GetFileName(certificatePath));
            }
        }
    }
}
