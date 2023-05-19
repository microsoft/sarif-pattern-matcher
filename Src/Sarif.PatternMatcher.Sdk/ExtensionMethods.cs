// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public static class ExtensionMethods
    {
        public static char RedactionChar => '?';

        /// <summary>
        /// Use an <cref>HttpClient</cref> instance to retrieve request response headers only.
        /// </summary>
        /// <param name="httpClient">The <cref>HttpClient</cref> instance to drive the request.</param>
        /// <param name="request">The request for which response headers should be retrieved.</param>
        /// <returns>The <cref>HttpResponseMessage</cref> returned by the request.</returns>
        public static HttpResponseMessage ReadResponseHeaders(this HttpClient httpClient, HttpRequestMessage request)
        {
            return httpClient
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                .GetAwaiter()
                .GetResult();
        }

        /// <summary>
        /// Use an <cref>HttpClient</cref> instance to retrieve request response headers only.
        /// </summary>
        /// <param name="httpClient">The <cref>HttpClient</cref> instance to drive the request.</param>
        /// <param name="uri">The Uri the request is sent to.</param>
        /// <returns>The <cref>HttpResponseMessage</cref> returned by the request.</returns>
        public static HttpResponseMessage ReadResponseHeaders(this HttpClient httpClient, string uri)
        {
            return httpClient
                .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead)
                .GetAwaiter()
                .GetResult();
        }

        /// <summary>
        /// Merges a dictionary of values into an HttpRequestHeaders instance.
        /// </summary>
        /// <param name="httpRequestHeaders">The HttpRequestHeaders instance to merge data into.</param>
        /// <param name="valuesToMerge">A collection of KeyValuePairs to merge into the request headers.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="valuesToMerge"/> is null.</exception>
        public static void Merge(this HttpRequestHeaders httpRequestHeaders,
                                 IEnumerable<KeyValuePair<string, string>> valuesToMerge)
        {
            if (valuesToMerge == null)
            {
                throw new ArgumentNullException(nameof(valuesToMerge));
            }

            foreach (KeyValuePair<string, string> entry in valuesToMerge)
            {
                if (httpRequestHeaders.Contains(entry.Key))
                {
                    httpRequestHeaders.Remove(entry.Key);
                }

                httpRequestHeaders.Add(entry.Key, entry.Value);
            }
        }

        public static string Truncate(this string text, int lengthExclusiveOfEllipsis = 6)
        {
            text ??= string.Empty;
            string truncatedText = text.TrimEnd('=');
            string suffix = new string('=', text.Length - truncatedText.Length);

            if (truncatedText.Length <= lengthExclusiveOfEllipsis)
            {
                return text;
            }

            truncatedText = truncatedText.Substring(truncatedText.Length - lengthExclusiveOfEllipsis);

            bool charsElided = truncatedText.Length != text.Length;

            // "\u2026" == "…"
            return (charsElided ? "\u2026" : string.Empty) +
                   truncatedText.Substring(truncatedText.Length - lengthExclusiveOfEllipsis) +
                   (charsElided ? suffix : string.Empty);
        }

        public static string Anonymize(this string text, int lengthExclusiveOfEllipsis = 6)
        {
            text ??= string.Empty;
            string trimmedText = text.TrimEnd('=');
            string suffix = new string('=', text.Length - trimmedText.Length);

            // Get the anonymized text, absent the ellipse prefix.
            string truncatedText = trimmedText.Truncate(lengthExclusiveOfEllipsis);

            if (truncatedText.StartsWith("\u2026"))
            {
                truncatedText = truncatedText.Substring(1);
            }

            int prefixLength = trimmedText.Length - truncatedText.Length;
            string prefix = new string(RedactionChar, prefixLength >= 0 ? prefixLength : 0);
            return prefix +
                   truncatedText +
                   suffix;
        }

        /// <summary>
        /// Determines whether the input string contains an uppercase letter, lowercase letter, and digit.
        /// </summary>
        /// <param name="text">The input string.</param>
        /// <returns>true if the input string contains an uppercase letter and lowercase letter and digit; otherwise, false.</returns>
        public static bool ContainsDigitLowercaseAndUppercaseLetter(this string text)
        {
            /*
                Assuming a random string of length L for this proof

                Let
                x1 = {strings with at least one uppercase}
                x2 = {strings with at least one lowercase}
                x3 = {string with at least one digit}

                '+' = set union, '.' = set intersection, and '!' = set complement.

                What we seek: P(x1 . x2 . x3) = 1 - P (!x1 + !x2 + !x3)

                So we need to compute the size of the set (!x1 + !x2 + !x3).

                By De Morgan's law:

                (!x1 + !x2 + !x3) = !x1 + !x2 + !x3 - (!x1 . !x2) - (!x2 . !x3) - (!x3 . !x1) + (!x1 . !x2 . !x3)

                !x1 = all strings with no uppercase = (36)^L | (26 lowercase alphabet chars + 10 digits) ^ (string length)
                !x2 = all strings with no lowercase = (36)^L | (26 uppercase alphabet chars + 10 digits) ^ (string length)
                !x3 = all strings with no digits = (52)^L    | (26 lowercase + 26 uppercase alphabet chars) ^ (string length)

                !x1 . !x2 = all strings with no uppercase and no lowercase = all strings with only digits = (10)^L
                !x2 . !x3 = all strings with no lowercase and no digits = all strings with only uppercase = (26)^L
                !x3 . !x1 = all strings with no digits and no uppercase = all strings with only lowercase = (26)^L

                !x1. !x2. !x3 = all strings with no uppercase, no lowercase, no digits = 0

                So the final solution:

                1  - (52 ^ L)/(62 ^ L) - (36 ^ L)/(62 ^ L)  - (36 ^ L)/(62 ^ L) + ((26 ^ L)/(62 ^ L) + (26 ^ L)/(62 ^ L) + (10 ^ L)/(62 ^ L)

                Results:
                Random strings length | Probability they contain upper, lower, and digit
                                   25 | ~98.769%
                                   32 | ~99.641%
                                   40 | ~99.912%
                                   42 | ~99.938%
                                   52 | ~99.989%
                                   86 | ~99.999%

                CAUTION: This proof is under the assumption that every secret checked will be a random string. Variable names are
                a good example of strings that would fit the length requirement, but are less likely to contain digits for example.
             */

            return text.ContainsLowercaseAndUppercaseLetter() && text.ContainsMinimumCountOfDigits(1);
        }

        /// <summary>
        /// Determines whether the input string contains both digit and letter.
        /// </summary>
        /// <param name="text">The input string.</param>
        /// <returns>true if the input string contains both digit and letter; otherwise, false.</returns>
        public static bool ContainsDigitAndLetter(this string text)
        {
            return text.ContainsMinimumCountOfDigits(1) && text.ContainsMinimumCountOfLetters(1);
        }

        /// <summary>
        /// Determines whether the input string contains both lowercase and uppercase letter.
        /// </summary>
        /// <param name="text">The input string.</param>
        /// <returns>true if the input string contains both lowercase and uppercase letter; otherwise, false.</returns>
        public static bool ContainsLowercaseAndUppercaseLetter(this string text)
        {
            return text.ContainsMinimumCountOfLowercaseLetters(1) && text.ContainsMinimumCountOfUppercaseLetters(1);
        }

        /// <summary>
        /// Determines whether the input string contains mininum count of digits.
        /// </summary>
        /// <param name="text">The input string.</param>
        /// <param name="lowerBound">The minimum count of digits required.</param>
        /// <returns>true if the input string contains minimum count of digits; otherwise, false.</returns>
        public static bool ContainsMinimumCountOfDigits(this string text, int lowerBound)
        {
            int digitCount = 0;

            foreach (char c in text)
            {
                if (char.IsDigit(c))
                {
                    digitCount++;
                }

                if (digitCount >= lowerBound)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Determines whether the input string contains minimum count of letters.
        /// </summary>
        /// <param name="text">The input string.</param>
        /// <param name="lowerBound">The minimum count of letters required.</param>
        /// <returns>true if the input string contains minimum count of letters; otherwise, false.</returns>
        public static bool ContainsMinimumCountOfLetters(this string text, int lowerBound)
        {
            int letterCount = 0;

            foreach (char c in text)
            {
                if (char.IsLetter(c))
                {
                    letterCount++;
                }

                if (letterCount >= lowerBound)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Determines whether the input string contains minimum count of uppercase letters.
        /// </summary>
        /// <param name="text">The input string.</param>
        /// <param name="lowerBound">The minimum count of uppercase letters required.</param>
        /// <returns>true if the input string contains minimum count of uppercase letters; otherwise, false.</returns>
        public static bool ContainsMinimumCountOfUppercaseLetters(this string text, int lowerBound)
        {
            int upperCount = 0;

            foreach (char c in text)
            {
                if (char.IsUpper(c))
                {
                    upperCount++;
                }

                if (upperCount >= lowerBound)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Determines whether the input string contains minimum count of lowercase letters.
        /// </summary>
        /// <param name="text">The input string.</param>
        /// <param name="lowerBound">The minimum count of lowercase letters required.</param>
        /// <returns>true if the input string contains minimum count of lowercase letters; otherwise, false.</returns>
        public static bool ContainsMinimumCountOfLowercaseLetters(this string text, int lowerBound)
        {
            int lowerCount = 0;

            foreach (char c in text)
            {
                if (char.IsLower(c))
                {
                    lowerCount++;
                }

                if (lowerCount >= lowerBound)
                {
                    return true;
                }
            }

            return false;
        }
    }
}
