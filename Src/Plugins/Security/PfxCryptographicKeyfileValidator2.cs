// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    internal static class PfxCryptographicKeyfileValidator2
    {
#pragma warning disable IDE0060 // Remove unused parameter
        public static string IsValid(
            ref string matchedPattern,
            ref Dictionary<string, string> groups,
            ref bool performDynamicValidation,
            ref string failureLevel,
            ref string fingerprint)
        {
#pragma warning restore IDE0060
            fingerprint = $"[cert={matchedPattern}]";

            // This plugin does not perform any dynamic validation.
            // We therefore set this setting to false. This is a
            // clue to the caller not to warn the user that, e.g.,
            // dynamic analysis was available but not exercised.
            performDynamicValidation = false;

            return TryLoadCertificate(matchedPattern).ToString();
        }

        private static ValidationState TryLoadCertificate(string certificatePath)
        {
            X509Certificate2 certificate = null;
            try
            {
                // If this certificate needs a password or it is a bundle, it will throw an exception.
                certificate = new X509Certificate2(certificatePath);

                return certificate.PrivateKey != null ? ValidationState.Authorized : ValidationState.NoMatch;
            }
            catch (CryptographicException ex)
            {
                return ex.Message switch
                {
                    "Cannot find the original signer." => TryLoadCertificateCollection(certificatePath),
                    "The specified network password is not correct." => ValidationState.Unknown,
                    _ => ValidationState.Unknown,
                };
            }
            catch (Exception)
            {
                return ValidationState.Unknown;
            }
            finally
            {
                certificate?.Dispose();
            }
        }

        private static ValidationState TryLoadCertificateCollection(string certificatePath)
        {
            var certificates = new X509Certificate2Collection();
            try
            {
                // If this certificate needs a password, it will throw an exception.
                certificates.Import(certificatePath);
                foreach (X509Certificate2 certificate in certificates)
                {
                    if (certificate.PrivateKey != null)
                    {
                        // Private key detected.
                        return ValidationState.Authorized;
                    }
                }

                return ValidationState.NoMatch;
            }
            catch (Exception)
            {
                return ValidationState.Unknown;
            }
        }
    }
}
