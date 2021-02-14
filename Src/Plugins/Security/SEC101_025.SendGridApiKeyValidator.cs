// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    public class SendGridApiKeyValidator : ValidatorBase
    {
        internal static SendGridApiKeyValidator Instance;

        static SendGridApiKeyValidator()
        {
            Instance = new SendGridApiKeyValidator();
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

        public static string IsValidDynamic(ref string fingerprint, ref string message)
        {
            return ValidatorBase.IsValidDynamic(Instance,
                                                ref fingerprint,
                                                ref message);
        }

        protected override string IsValidStaticHelper(ref string matchedPattern,
                                                      ref Dictionary<string, string> groups,
                                                      ref string failureLevel,
                                                      ref string fingerprintText,
                                                      ref string message)
        {
            string key = groups["key"];

            fingerprintText = new Fingerprint
            {
                Key = key,
            }.ToString();

            return nameof(ValidationState.Unknown);
        }

        protected override string IsValidDynamicHelper(ref string fingerprintText,
                                                       ref string message)
        {
            var fingerprint = new Fingerprint(fingerprintText);

            string account = "apikey";
            string key = fingerprint.Key;
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

                    // Base64-encode the api key. 235 is authorized, 535 is not.
                    key = Convert.ToBase64String(Encoding.UTF8.GetBytes(key));
                    Send(reader, writer, out response, $"{key}\r\n", "235");
                }
            }
            catch (InvalidOperationException e)
            {
                if (e.Message != nameof(ValidationState.Unauthorized))
                {
                    message = $"An unexpected server response was received: '{response}'";
                }

                return e.Message;
            }
            catch (Exception e)
            {
                return ReturnUnhandledException(ref message, e);
            }

            return nameof(ValidationState.Authorized);
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
