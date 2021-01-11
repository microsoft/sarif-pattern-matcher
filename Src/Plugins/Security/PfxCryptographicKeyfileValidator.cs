// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    internal static class PfxCryptographicKeyfileValidator
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

            // This plugin does not perform any dynamic validation.
            // We therefore set this setting to false. This is a
            // clue to the caller not to warn the user that, e.g.,
            // dynamic analysis was available but not exercised.
            performDynamicValidation = false;

            string thumprint = string.Empty;
            string validationState = TryLoadCertificate(matchedPattern, ref thumprint);
            fingerprint = $"[thumbprint={thumprint}]";
            return validationState;
        }

        private static string TryLoadCertificate(string certificatePath, ref string thumprint)
        {
            X509Certificate2 certificate = null;
            try
            {
                // If this certificate needs a password or it is a bundle, it will throw an exception.
                certificate = new X509Certificate2(certificatePath);
                thumprint = certificate.Thumbprint;
                return certificate.PrivateKey != null
                    ? nameof(ValidationState.Authorized)
                    : nameof(ValidationState.NoMatch);
            }
            catch (CryptographicException e)
            {
                return e.Message switch
                {
                    "Cannot find the original signer." => TryLoadCertificateCollection(certificatePath, ref thumprint),
                    _ => ValidatorBase.CreateReturnValueForUnknownException(e, certificatePath),
                };
            }
            catch (Exception e)
            {
                return ValidatorBase.CreateReturnValueForUnknownException(e, certificatePath);
            }
            finally
            {
                certificate?.Dispose();
            }
        }

        private static string TryLoadCertificateCollection(string certificatePath, ref string thumprint)
        {
            var certificates = new X509Certificate2Collection();
            try
            {
                // If this certificate needs a password, it will throw an exception.
                certificates.Import(certificatePath);
                var sb = new StringBuilder();
                string state = nameof(ValidationState.NoMatch);
                foreach (X509Certificate2 certificate in certificates)
                {
                    sb.Append(certificate.Thumbprint);
                    sb.Append(";");
                    if (certificate.PrivateKey != null)
                    {
                        // Private key detected.
                        state = nameof(ValidationState.Authorized);
                    }
                }

                if (sb.Length > 0)
                {
                    sb.Remove(sb.Length - 1, 1);
                }

                thumprint = sb.ToString();
                return state;
            }
            catch (Exception e)
            {
                return ValidatorBase.CreateReturnValueForUnknownException(e, certificatePath);
            }
        }
    }
}
