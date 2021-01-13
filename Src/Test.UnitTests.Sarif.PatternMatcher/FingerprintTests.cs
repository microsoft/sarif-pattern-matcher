﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

using FluentAssertions;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class FingerprintTests
    {
        [Fact]
        public void Fingerprint_KeyNamesMatchProperties()
        {
            // Invariant: every string property on the fingerprint
            // should have a corresponding key name string constant.

            List<string> unexpectedConditions = new List<string>();

            var expectedKeyNames = new HashSet<string>();

            Type type = typeof(Fingerprint);

            foreach (PropertyInfo pi in type.GetProperties())
            {
                expectedKeyNames.Add(pi.Name + "KeyName");
            }

            foreach (FieldInfo fi in type.GetFields())
            {
                if (!expectedKeyNames.Contains(fi.Name))
                {
                    unexpectedConditions.Add(
                        $"{Environment.NewLine}Could not find property matching existing key name field: {fi.Name}.");
                    continue;
                }
                expectedKeyNames.Remove(fi.Name);
            }

            foreach (string keyName in expectedKeyNames)
            {
                unexpectedConditions.Add(
                    $"{Environment.NewLine}Could not find key name field to match existing property: {keyName}.");
            }

            unexpectedConditions.Should().BeEmpty();
        }

        [Fact]
        public void Fingerprint_KeyNamesAreNotDuplicated()
        {
            var duplicatedFieldNames = new List<string>();

            var keyNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            Type type = typeof(Fingerprint);
            foreach (FieldInfo fi in type.GetFields())
            {
                string fieldValue = (string)fi.GetValue(null);
                if (keyNames.Contains(fieldValue))
                {
                    duplicatedFieldNames.Add(
                        $"{Environment.NewLine}Field '{fi.Name}' has a value which is shared by another key name field: '{fieldValue}'.");
                }
                keyNames.Add(fieldValue);
            }

            duplicatedFieldNames.Should().BeEmpty();
        }

        [Fact]
        public void Fingerprint_AllPropertiesPersistedInToString()
        {
            // Invariant: fingerprint.ToString() should
            // render all property values if set.

            var fingerprint = new Fingerprint();
            var propertyValues = new Dictionary<string, string>();

            Type type = typeof(Fingerprint);

            foreach (PropertyInfo pi in type.GetProperties())
            {
                string guidText = Guid.NewGuid().ToString();
                object boxed = fingerprint;
                pi.SetMethod.Invoke(boxed, new[] { guidText });
                fingerprint = (Fingerprint)boxed;
                propertyValues[guidText] = pi.Name;
            }

            string fingerprintText = fingerprint.ToString();

            List<string> unexpectedConditions = new List<string>();

            foreach (string guidText in propertyValues.Keys)
            {
                string keyName = GetKeyNameForProperty(propertyValues[guidText]);
                if (!fingerprintText.Contains(guidText) ||
                    !fingerprintText.Contains($"[{keyName}={guidText}]"))
                {
                    unexpectedConditions.Add(
                        $"{Environment.NewLine}ToString() not rendering property: {propertyValues[guidText]}.");
                }
            }

            if (unexpectedConditions.Count > 0)
            {
                unexpectedConditions.Add(
                    $"{Environment.NewLine}Rendered fingerprint was: {fingerprint}.");
            }

            unexpectedConditions.Should().BeEmpty();
        }

        private string GetKeyNameForProperty(string propertyName)
        {
            FieldInfo fi = typeof(Fingerprint).GetField($"{propertyName}KeyName");
            return (string)fi.GetValue(null);
        }

        [Fact]
        public void Fingerprint_IndividualPropertiesPersistedInToString()
        {
            // Invariant: fingerprint.ToString() should
            // render individual properties when set

            Type type = typeof(Fingerprint);
            List<string> toStringUnexpectedConditions = new List<string>();
            List<string> roundTrippingUnexpectedConditions = new List<string>();

            foreach (PropertyInfo pi in type.GetProperties())
            {
                var fingerprint = new Fingerprint();
                string guidText = Guid.NewGuid().ToString();
                object boxed = fingerprint;
                pi.SetMethod.Invoke(boxed, new[] { guidText });
                fingerprint = (Fingerprint)boxed;
                string keyName = GetKeyNameForProperty(pi.Name);
                if (!fingerprint.ToString().Contains($"[{keyName}={guidText}]"))
                {
                    toStringUnexpectedConditions.Add(
                        $"{Environment.NewLine}ToString() not rendering property value " +
                        $"for: {pi.Name}. Actual fingerprint was: {fingerprint}.");
                    continue;
                }

                string expectedFingerprint = fingerprint.ToString();
                var roundtrippedFingerprint = new Fingerprint(expectedFingerprint);
                string actualFingerprint = roundtrippedFingerprint.ToString();

                if (!actualFingerprint.Equals(expectedFingerprint))
                {
                    roundTrippingUnexpectedConditions.Add(
                        $"{Environment.NewLine}(Actual roundtripped fingerprint) {actualFingerprint} != (expected) {expectedFingerprint}."
                        );
                }
            }

            toStringUnexpectedConditions.Should().BeEmpty();
        }

        [Fact]
        public void Fingerprint_EmptyObjectToStringReturnsStringEmpty()
        {
            var fingerprint = new Fingerprint();
            fingerprint.ToString().Should().BeEmpty();
        }

        [Fact]
        public void Fingerprint_SetProperty()
        {
            var failedTestCases = new List<string>();

            Type type = typeof(Fingerprint);
            foreach (PropertyInfo pi in type.GetProperties())
            {
                string expected = Guid.NewGuid().ToString();
                var fingerprint = new Fingerprint();

                FieldInfo fi = type.GetField($"{pi.Name}KeyName");
                string key = (string)fi.GetValue(fingerprint);

                object boxed = fingerprint;
                MethodInfo mi = type.GetMethod("SetProperty");
                mi.Invoke(boxed, new[] { key, expected });
                fingerprint = (Fingerprint)boxed;

                string actual = (string)pi.GetGetMethod().Invoke(fingerprint, null);
                if (actual != expected)
                {
                    failedTestCases.Add(
                        $"{Environment.NewLine}SetProperty(\"{key}\", {expected}) did not persist " +
                        $"property value which was observed to be '{actual}'."
                    );
                }
            }

            failedTestCases.Should().BeEmpty();
        }

        [Fact]
        public void Fingerprint_ValuesParseCorrectlyAsEvidencedByToStringEquivalence()
        {
            var failedTestCases = new List<string>();

            foreach (FingerprintTestCase testCase in s_workingTestCases)
            {
                string actual = null;

                try
                {
                    actual = new Fingerprint(testCase.Text).ToString();
                }
                catch (Exception e)
                {
                    failedTestCases.Add(
                        $"{Environment.NewLine}'{e.GetType().Name}' exception thrown trying to initialize fingerprint '{testCase.Text}'.");
                    continue;
                }

                string expected = testCase.Expected.ToString();
                if (!actual.Equals(expected))
                {
                    failedTestCases.Add(
                        $"{Environment.NewLine}'{testCase.Title}' failed. Expected result '{expected}' but observed '{actual}'.");
                }
            }

            failedTestCases.Should().BeEmpty();
        }

        [Fact]
        public void Fingerprint_ValuesParseCorrectlyAsEvidencedByObjectEquivalence()
        {
            var failedTestCases = new List<string>();

            foreach (FingerprintTestCase testCase in s_workingTestCases)
            {
                var actual = new Fingerprint();

                try
                {
                    actual = new Fingerprint(testCase.Text);
                }
                catch (Exception e)
                {
                    failedTestCases.Add(
                        $"{Environment.NewLine}'{e.GetType().Name}' exception thrown trying to initialize" +
                        $"fingerprint '{testCase.Text}'.{Environment.NewLine}Exception message: '{e.Message}'");
                    continue;
                }

                Fingerprint expected = testCase.Expected;
                if (!actual.Equals(expected))
                {
                    failedTestCases.Add(
                        $"{Environment.NewLine}Object comparison for '{testCase.Title}' failed. Expected fingerprint was '{expected}', observed was '{actual}'.");
                }
            }

            failedTestCases.Should().BeEmpty();
        }

        [Fact]
        public void Fingerprint_MalformedValuesRaiseExceptions()
        {
            var failedTestCases = new List<string>();

            foreach (FingerprintTestCase testCase in s_exceptionalTestCases)
            {
                try
                {
                    var actual = new Fingerprint(testCase.Text);
                }
                catch (Exception e)
                {
                    Type type = e.GetType();
                    if (type != testCase.ExceptionType)
                    {
                        failedTestCases.Add(
                            $"{Environment.NewLine}'{testCase.Title}': " +
                            $"Observed unexpected exception type: {type.Name}.");
                    }
                    continue;
                }
                failedTestCases.Add(
                    $"{Environment.NewLine}'{testCase.Title}': " +
                    $"No '{testCase.ExceptionType.Name}' exception was raised.");
            }

            failedTestCases.Should().BeEmpty();
        }

        private static readonly FingerprintTestCase[] s_workingTestCases = new[]
        {
            new FingerprintTestCase {
                Title = "Single key (Host).",
                Text = $"[{Fingerprint.HostKeyName}=Host]",
                Expected = new Fingerprint { Host = "Host" }},

            new FingerprintTestCase {
                Title = "Two keys (Account & Host) in alphabetical order.",
                Text = $"[{Fingerprint.AccountKeyName}=Account][{Fingerprint.HostKeyName}=Host]",
                Expected = new Fingerprint { Host = "Host", Account = "Account" }},
        };

        private static readonly FingerprintTestCase[] s_exceptionalTestCases = new[]
        {
            new FingerprintTestCase {
                Title = "Null value.",
                Text = null,
                ExceptionType = typeof(ArgumentNullException) },

            new FingerprintTestCase {
                Title = "Missing terminal right bracket.",
                Text = $"[{Fingerprint.AccountKeyName}=Account][{Fingerprint.HostKeyName}=Host",
                ExceptionType = typeof(ArgumentException) },

            new FingerprintTestCase {
                Title = "Duplicated keys (Uri & Uri).",
                Text = $"[{Fingerprint.UriKeyName}=Uri][{Fingerprint.UriKeyName}=Uri]",
                ExceptionType = typeof(ArgumentException) },

            new FingerprintTestCase {
                Title = "Two keys (Host and Account) in non-alphabetical order.",
                Text = $"[{Fingerprint.HostKeyName}=Host][{Fingerprint.AccountKeyName}=Account]",
                ExceptionType = typeof(ArgumentException) },

            new FingerprintTestCase {
                Title = "Two keys (Account & Host) in alphabetical order with spaces.",
                Text = $"[{Fingerprint.AccountKeyName}=Account] [{Fingerprint.HostKeyName}=Host]",
                ExceptionType = typeof(ArgumentException) },

            new FingerprintTestCase {
                Title = "Key name (NON_EXISTENT) does not exist.",
                Text = $"[NON_EXISTENT=RandomValue]",
                ExceptionType = typeof(ArgumentException) },
        };

        internal struct FingerprintTestCase
        {
            public string Title;
            public string Text;
            public Fingerprint Expected;
            public Type ExceptionType;
        }
    }
}
