// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class SendGridApiKeyValidator : ValidatorBase
    {
        internal static SendGridApiKeyValidator Instance;

        static SendGridApiKeyValidator()
        {
            Instance = new SendGridApiKeyValidator();
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

        public static ValidationState IsValidDynamic(ref Fingerprint fingerprint,
                                                     ref string message,
                                                     ref Dictionary<string, string> options,
                                                     ref ResultLevelKind resultLevelKind)
        {
            return IsValidDynamic(Instance,
                                  ref fingerprint,
                                  ref message,
                                  ref options,
                                  ref resultLevelKind);
        }

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(ref string matchedPattern,
                                                                             ref Dictionary<string, string> groups,
                                                                             ref string message)
        {
            if (!groups.TryGetValue("secret", out string secret))
            {
                return ValidationResult.NoMatch;
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint
                {
                    Secret = secret,
                    Platform = nameof(AssetPlatform.SendGrid),
                },
                ValidationState = ValidationState.Unknown,
            };

            return new[] { validationResult };
        }

        protected override ValidationState IsValidDynamicHelper(ref Fingerprint fingerprint,
                                                                ref string message,
                                                                ref Dictionary<string, string> options,
                                                                ref ResultLevelKind resultLevelKind)
        {
            string account = "apikey";
            string secret = fingerprint.Secret;
            const string host = "smtp.sendgrid.net";

            string response = string.Empty;

            try
            {
                using var tcpClient = new TcpClient();
                tcpClient.ConnectAsync(host, 465).GetAwaiter().GetResult();

                using (var sslStream = new SslStream(tcpClient.GetStream()))
                {
                    sslStream.AuthenticateAsClientAsync(host, null, SslProtocols.Tls12, false).GetAwaiter().GetResult();

                    // Encoding is ISO-8859-1 Western European
                    using var reader = new StreamReader(sslStream, Encoding.GetEncoding(28591));
                    using var writer = new StreamWriter(sslStream, Encoding.GetEncoding(28591));

                    response = reader.ReadLine();
                    if (!response.StartsWith("220"))
                    {
                        throw new InvalidOperationException(nameof(ValidationState.Unknown));
                    }

                    // Say hello and request basic authentication.
                    Send(reader, writer, out response, $"HELO\r\n", "250");
                    Send(reader, writer, out response, $"AUTH LOGIN\r\n", "334", "250");

                    // Send the account name. 'apikey' is the name for SendGrid SMTP access.
                    account = Convert.ToBase64String(Encoding.UTF8.GetBytes(account));
                    Send(reader, writer, out response, $"{account}\r\n", "334");

                    // Base64-encode the api secret. 235 is authorized, 535 is not.
                    secret = Convert.ToBase64String(Encoding.UTF8.GetBytes(secret));
                    Send(reader, writer, out response, $"{secret}\r\n", "235");
                }
            }
            catch (InvalidOperationException e)
            {
                if (e.Message != nameof(ValidationState.Unauthorized))
                {
                    message = $"An unexpected server response was received: '{response}'";
                }

                return (ValidationState)Enum.Parse(typeof(ValidationState), e.Message);
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e);
            }

            return ValidationState.Authorized;
        }

        private static string Send(StreamReader reader,
                                   StreamWriter writer,
                                   out string response,
                                   string data,
                                   string success,
                                   string @continue = null)
        {
            writer.WriteAsync(data)
                .GetAwaiter()
                .GetResult();
            writer.FlushAsync().GetAwaiter().GetResult();

            while ((response = reader.ReadLineAsync().GetAwaiter().GetResult()) != null)
            {
                if (response.StartsWith(success))
                {
                    break;
                }

                if (@continue != null && response.StartsWith(@continue))
                {
                    continue;
                }

                if (response.StartsWith("535"))
                {
                    throw new InvalidOperationException(nameof(ValidationState.Unauthorized));
                }

                throw new InvalidOperationException(nameof(ValidationState.Unknown));
            }

            return response;
        }
    }
}
