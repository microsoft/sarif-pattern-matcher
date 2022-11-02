// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk
{
    public static class ExtensionMethods
    {
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

        public static char RedactionChar => '?';

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
    }
}
