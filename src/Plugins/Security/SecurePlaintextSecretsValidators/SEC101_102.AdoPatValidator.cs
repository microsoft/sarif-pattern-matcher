// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;
using Microsoft.RE2.Managed;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security
{
    [ValidatorDescriptor("SEC101/102")]
    public class AdoPatValidator : StaticValidatorBase
    {
        /// <summary>
        /// Magic number to validate PAT checksum.
        /// </summary>
        private const uint ChecksumPat = 0xE0B9692D;

        /// <summary>
        /// Magic number to validate ADO application secret checksum.
        /// </summary>
        private const uint ChecksumAdoAppSecret = 0x1019F92E;

        protected override IEnumerable<ValidationResult> IsValidStaticHelper(IDictionary<string, FlexMatch> groups)
        {
            FlexMatch secret = groups["secret"];

            ValidationState state =
                IsChecksumValid(secret.Value, ChecksumPat) ||
                IsChecksumValid(secret.Value, ChecksumAdoAppSecret) ?
                    ValidationState.Unknown :
                    ValidationState.NoMatch;

            if (state == ValidationState.NoMatch)
            {
                return ValidationResult.CreateNoMatch();
            }

            var validationResult = new ValidationResult
            {
                Fingerprint = new Fingerprint()
                {
                    Secret = secret.Value,
                    Platform = nameof(AssetPlatform.AzureDevOps),
                },
                ValidationState = state,
            };

            return new[] { validationResult };
        }

        /// <summary>
        /// Given a string, validate that it has a valid checksum.
        /// </summary>
        /// <param name="input">String to checksum validate.</param>
        /// <param name="magicNumber">Magic number to use to validating checksum.</param>
        /// <returns>True if checksum is valid.</returns>
        private static bool IsChecksumValid(string input, uint magicNumber)
        {
            byte[] inputBytes = ConvertFromBase32(input);

            // Extract out the bytes which are not the checksum
            byte[] tokenBytes = new byte[28];
            Array.Copy(inputBytes, 0, tokenBytes, 0, 2);
            Array.Copy(inputBytes, 3, tokenBytes, 2, 4);
            Array.Copy(inputBytes, 9, tokenBytes, 6, 13);
            Array.Copy(inputBytes, 23, tokenBytes, 19, 9);

            // Calculate the checksum
            uint newChecksum;
            {
                uint crc32 = Crc32.Calculate(tokenBytes);

                // XOR the calculated checksum with a magic number.
                newChecksum = crc32 ^ magicNumber;
            }

            // Extract the embedded checksum from the input
            // in reverse-order (little-endian), and convert to uint.
            byte[] originalChecksumBytes = new byte[4];
            originalChecksumBytes[0] = inputBytes[22];
            originalChecksumBytes[1] = inputBytes[8];
            originalChecksumBytes[2] = inputBytes[7];
            originalChecksumBytes[3] = inputBytes[2];
            uint originalChecksum = BitConverter.ToUInt32(originalChecksumBytes, 0);

            return originalChecksum.Equals(newChecksum);
        }

        private static byte[] ConvertFromBase32(string inputString)
        {
            const int InputPerByteSize = 8;
            const int OutputPerByteSize = 5;
            const string AlphabetLower = "abcdefghijklmnopqrstuvwxyz234567";
            const string AlphabetUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

            if (string.IsNullOrEmpty(inputString))
            {
                return Array.Empty<byte>();
            }

            int outputSize = inputString.Length * OutputPerByteSize / InputPerByteSize;
            if (outputSize == 0)
            {
                throw new ArgumentException("Input string invalid base32. Empty output array.");
            }

            int inputOffset = 0;
            int inputPosition = 0;
            byte[] output = new byte[outputSize];
            for (int outputPosition = 0; outputPosition < output.Length; outputPosition++)
            {
                int outputOffset = 0;

                while (outputOffset < InputPerByteSize)
                {
                    int currentByte = AlphabetLower.IndexOf(inputString[inputPosition]);
                    if (currentByte < 0)
                    {
                        currentByte = AlphabetUpper.IndexOf(inputString[inputPosition]);

                        if (currentByte < 0)
                        {
                            throw new ArgumentException("Invalid base32 character \"inputString[inputPosition]\"");
                        }
                    }

                    int size1 = OutputPerByteSize - inputOffset;
                    int size2 = InputPerByteSize - outputOffset;
                    int bitsRemaining = size1 < size2 ? size1 : size2;
                    inputOffset += bitsRemaining;
                    outputOffset += bitsRemaining;
                    output[outputPosition] <<= bitsRemaining;

                    int offset = OutputPerByteSize - inputOffset;
                    byte outputByte = (byte)(currentByte >> offset);
                    output[outputPosition] |= outputByte;

                    if (inputOffset >= OutputPerByteSize)
                    {
                        inputPosition++;
                        inputOffset = 0;
                    }
                }
            }

            return output;
        }
    }
}
