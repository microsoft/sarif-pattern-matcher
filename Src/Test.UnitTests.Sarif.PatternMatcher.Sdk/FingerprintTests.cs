// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

using FluentAssertions;

using Microsoft.CodeAnalysis.Sarif.PatternMatcher.Sdk;

using Newtonsoft.Json;

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

            var unexpectedConditions = new List<string>();

            var expectedKeyNames = new HashSet<string>();

            Type type = typeof(Fingerprint);

            foreach (PropertyInfo pi in GetTestableFingerprintProperties())
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
            Fingerprint_AllPropertiesPersistedInToStringHelper(jsonFormat: true);
            Fingerprint_AllPropertiesPersistedInToStringHelper(jsonFormat: false);
        }

        private static void Fingerprint_AllPropertiesPersistedInToStringHelper(bool jsonFormat)
        {
            // Invariant: fingerprint.ToString() should
            // render all property values if set.

            string prefix = jsonFormat ? "\"" : "[";
            string suffix = jsonFormat ? "\"" : "]";
            string separator = jsonFormat ? "\":\"" : "=";

            var fingerprint = new Fingerprint();
            var propertyValues = new Dictionary<string, string>();

            Type type = typeof(Fingerprint);

            foreach (PropertyInfo pi in GetTestableFingerprintProperties())
            {
                string guidText = Guid.NewGuid().ToString() + "/" + Guid.NewGuid().ToString();
                object boxed = fingerprint;
                pi.SetMethod.Invoke(boxed, new[] { guidText });
                fingerprint = (Fingerprint)boxed;
                propertyValues[guidText] = pi.Name;
            }

            var emptyDenyList = new List<string>();
            string fingerprintText = Fingerprint.ToString(fingerprint, emptyDenyList, jsonFormat);

            // If we are operating against JSON representation,
            // let's make sure that the data returned is valid JSON.
            if (jsonFormat)
            {
                JsonConvert.DeserializeObject(fingerprintText).Should().NotBeNull();
            }

            var unexpectedConditions = new List<string>();

            foreach (string guidText in propertyValues.Keys)
            {
                string keyName = GetKeyNameForProperty(propertyValues[guidText]);
                if (!fingerprintText.Contains(guidText) ||
                    !fingerprintText.Contains($"{prefix}{keyName}{separator}{guidText}{suffix}"))
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

        [Fact]
        public void Fingerprint_IndividualPropertiesPersistedInToString()
        {
            Fingerprint_IndividualPropertiesPersistedInToStringHelper(jsonFormat: true);
            Fingerprint_IndividualPropertiesPersistedInToStringHelper(jsonFormat: false);
        }

        private static void Fingerprint_IndividualPropertiesPersistedInToStringHelper(bool jsonFormat)
        {
            // Invariant: fingerprint.ToString() should
            // render individual properties when set

            string prefix = jsonFormat ? "\"" : "[";
            string suffix = jsonFormat ? "\"" : "]";
            string separator = jsonFormat ? "\":\"" : "=";

            Type type = typeof(Fingerprint);
            var toStringUnexpectedConditions = new List<string>();
            var roundTrippingUnexpectedConditions = new List<string>();

            var emptyDenyList = new List<string>();

            foreach (PropertyInfo pi in GetTestableFingerprintProperties())
            {
                var fingerprint = new Fingerprint();
                string guidText = Guid.NewGuid().ToString() + "/" + Guid.NewGuid().ToString();
                object boxed = fingerprint;
                pi.SetMethod.Invoke(boxed, new[] { guidText });
                fingerprint = (Fingerprint)boxed;
                string keyName = GetKeyNameForProperty(pi.Name);
                string fingerprintText = Fingerprint.ToString(fingerprint, emptyDenyList, jsonFormat);

                // If we are operating against JSON representation,
                // let's make sure that the data returned is valid JSON.
                if (jsonFormat)
                {
                    JsonConvert.DeserializeObject(fingerprintText).Should().NotBeNull();
                }

                if (!fingerprintText.Contains($"{prefix}{keyName}{separator}{guidText}{suffix}"))
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
        public void Fingerprint_SetProperty_UnrecognizedKeyNames()
        {
            var fingerprint = new Fingerprint();

            fingerprint.SetProperty(Guid.NewGuid().ToString(), "test", ignoreRecognizedKeyNames: true);
            fingerprint.Should().BeEquivalentTo(default(Fingerprint));

            Action action = () => fingerprint.SetProperty(Guid.NewGuid().ToString(), "test");
            action.Should().Throw<ArgumentException>();
        }

        [Fact]
        public void Fingerprint_SetProperty()
        {
            var failedTestCases = new List<string>();

            Type type = typeof(Fingerprint);
            foreach (PropertyInfo pi in GetTestableFingerprintProperties())
            {
                string expected = Guid.NewGuid().ToString() + "/" + Guid.NewGuid().ToString();
                var fingerprint = new Fingerprint();

                FieldInfo fi = type.GetField($"{pi.Name}KeyName");
                string key = (string)fi.GetValue(fingerprint);

                object boxed = fingerprint;
                MethodInfo mi = type.GetMethod("SetProperty");
                mi.Invoke(boxed, new object[] { key, expected, false });
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

        private static IEnumerable<PropertyInfo> GetTestableFingerprintProperties()
        {
            foreach (PropertyInfo pi in typeof(Fingerprint).GetProperties())
            {
                if (pi.PropertyType != typeof(string)) { continue; }

                // These properties are tested exclusively through
                // the 'Part' property;
                if (pi.Name == "ResourceType" ||
                    pi.Name == "ResourceProvider")
                {
                    continue;
                }

                yield return pi;
            }
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

        [Fact]
        public void Fingerprint_ShouldNotBeInWrongOrder()
        {
            var fingerprint = new Fingerprint
            {
                Secret = "password",
                Platform = "platform",
            };

            string fingerprintText = fingerprint.ToString();

            var newFingerprint = new Fingerprint(fingerprintText);
            fingerprint.Should().Be(newFingerprint);
        }

        [Fact]
        public void Fingerprint_ShouldParseNormally()
        {
            string fingerprintText = "[id=[]123][port=123][secret=secret[]]";
            var fingerprint = new Fingerprint(fingerprintText);
            fingerprint.ToString().Should().Be(fingerprintText);
        }

        [Fact]
        public void Fingerprint_ShouldMergeNormally()
        {
            string previousFingerprint = "[host=host][part=part]";
            var fingerprint = new Fingerprint
            {
                Id = "id",
                Secret = "secret"
            };

            fingerprint.Merge(previousFingerprint);
            fingerprint.Id.Should().Be("id");
            fingerprint.Host.Should().Be("host");
            fingerprint.Part.Should().Be("part");
            fingerprint.Secret.Should().Be("secret");

            var sb = new StringBuilder();
            foreach (PropertyInfo property in GetTestableFingerprintProperties())
            {
                if (property.Name == "Id" || property.Name == "Host" || property.Name == "Part" || property.Name == "Secret")
                {
                    continue;
                }

                string value = (string)property.GetValue(fingerprint);

                if (!string.IsNullOrEmpty(value))
                {
                    sb.AppendLine($"Property '{property.Name}' should be null/empty.");
                }
            }

            sb.Length.Should().Be(0, because: sb.ToString());
        }

        [Fact]
        public void Fingerprint_PersistPathShouldNotHideDataFromValidationFingerprint()
        {
            const string id = "[id=id]";
            const string path = "[path=path]";
            var fingerprint = new Fingerprint($"{id}{path}");
            fingerprint.GetAssetFingerprint().Should().Be($"{id}{path}");
            fingerprint.GetValidationFingerprint().Should().Contain(path);
            string originalHash = fingerprint.GetValidationFingerprintHash();

            fingerprint.IgnorePathInFingerprint = true;
            fingerprint.GetAssetFingerprint().Should().Be(id);
            fingerprint.GetValidationFingerprint().Should().Contain(path);

            fingerprint = new Fingerprint
            {
                Id = "id",
                Path = "path"
            };
            fingerprint.GetAssetFingerprint().Should().Be($"{id}{path}");
            fingerprint.GetValidationFingerprint().Should().Contain(path);
            string firstHash = fingerprint.GetValidationFingerprintHash();
            firstHash.Should().Be(originalHash);

            fingerprint = new Fingerprint
            {
                Id = "id",
                Path = "path",
                IgnorePathInFingerprint = true
            };
            fingerprint.GetAssetFingerprint().Should().Be(id);
            fingerprint.GetValidationFingerprint().Should().Contain(path);
            string secondHash = fingerprint.GetValidationFingerprintHash();
            firstHash.Should().NotBe(secondHash);

            fingerprint = new Fingerprint
            {
                Id = "id",
                Path = "path",
                Secret = "secret"
            };
            fingerprint.GetAssetFingerprint().Should().Be($"{id}{path}");
            fingerprint.GetValidationFingerprint().Should().Be($"{id}{path}[secret=secret]");
            string thirdHash = fingerprint.GetValidationFingerprintHash();

            fingerprint.IgnorePathInFingerprint = true;
            fingerprint.GetAssetFingerprint().Should().Be($"{id}");
            fingerprint.GetValidationFingerprint().Should().Be($"{id}{path}[secret=secret]");
            string forthHash = fingerprint.GetValidationFingerprintHash();
            thirdHash.Should().NotBe(forthHash);
        }

        [Fact]
        public void Fingerprint_ToJsonShouldBeAValidJson()
        {
            var failedTestCases = new List<string>();

            foreach (FingerprintTestCase testCase in s_workingTestCases)
            {
                string actualJson = new Fingerprint(testCase.Text).GetComprehensiveFingerprint(jsonFormat: true);

                var newFingerprint = new Fingerprint(actualJson);

                if (!newFingerprint.Equals(testCase.Expected))
                {
                    failedTestCases.Add(
                        $"{Environment.NewLine}'{testCase.Title}' failed. Expected result '{testCase.Expected}' but observed '{newFingerprint}'.");
                }
            }

            failedTestCases.Should().BeEmpty();
        }

        [Fact]
        public void Fingerprint_EmptyFingerprint()
        {
            var fingerprint = new Fingerprint("");

            var sb = new StringBuilder();
            foreach (PropertyInfo property in GetTestableFingerprintProperties())
            {
                string value = (string)property.GetValue(fingerprint);

                if (!string.IsNullOrEmpty(value))
                {
                    sb.AppendLine($"Property '{property.Name}' should be null/empty.");
                }
            }

            sb.Length.Should().Be(0, because: sb.ToString());
        }

        [Fact]
        public void Fingerprint_ConstructingFromDictionaryShouldParseCorrectly()
        {
            var sb = new StringBuilder();
            for (int i = 0; i < s_dictionaryContructorTestCases.Length; i++)
            {
                DictionaryFingerprintTestCase testCase = s_dictionaryContructorTestCases[i];
                var currentFingerprint = new Fingerprint(testCase.Fingerprints);

                if (currentFingerprint != testCase.Expected)
                {
                    sb.Append($"The test '{testCase.Title}' failed. Expected result '{testCase.Expected}' but observed '{currentFingerprint}'.");
                }
            }
        }

        private static readonly FingerprintTestCase[] s_workingTestCases = new[]
        {
            new FingerprintTestCase {
                Title = "Single key (Host).",
                Text = $"[{Fingerprint.HostKeyName}=Host]",
                Expected = new Fingerprint { Host = "Host" }},

            new FingerprintTestCase {
                Title = "Two keys (Host & Id) in alphabetical order.",
                Text = $"[{Fingerprint.HostKeyName}=Host][{Fingerprint.IdKeyName}=Id]",
                Expected = new Fingerprint { Host = "Host", Id = "Id" }},

            new FingerprintTestCase {
                Title = "Resource provider and type.",
                Text = $"[{Fingerprint.PartKeyName}=ResourceType]",
                Expected = new Fingerprint { Part = "ResourceType" }},
        };

        private static readonly FingerprintTestCase[] s_exceptionalTestCases = new[]
        {
            new FingerprintTestCase {
                Title = "Null value.",
                Text = null,
                ExceptionType = typeof(ArgumentNullException) },

            new FingerprintTestCase {
                Title = "Missing terminal right bracket.",
                Text = $"[{Fingerprint.IdKeyName}=Id][{Fingerprint.HostKeyName}=Host]",
                ExceptionType = typeof(ArgumentException) },

            new FingerprintTestCase {
                Title = "Duplicated keys (Path & Path).",
                Text = $"[{Fingerprint.PathKeyName}=Path][{Fingerprint.PathKeyName}=Path]",
                ExceptionType = typeof(ArgumentException) },

            new FingerprintTestCase {
                Title = "Two keys (Host and Id) in non-alphabetical order.",
                Text = $"[{Fingerprint.IdKeyName}=Id][{Fingerprint.HostKeyName}=Host",
                ExceptionType = typeof(ArgumentException) },

            new FingerprintTestCase {
                Title = "Key name (NON_EXISTENT) does not exist.",
                Text = $"[NON_EXISTENT=RandomValue]",
                ExceptionType = typeof(ArgumentException) },
        };

        private static readonly DictionaryFingerprintTestCase[] s_dictionaryContructorTestCases = new[]
        {
            new DictionaryFingerprintTestCase
            {
                Title = "Square brackets fingerprints only.",
                Fingerprints = new Dictionary<string, string>
                {
                    { "asset-v1", "[id=id][part=part]" },
                    { "validation-v1", "[id=id][secret=secret]" },
                },
                Expected = new Fingerprint
                {
                    Id = "id",
                    Part = "part",
                    Secret = "secret",
                }
            },
            new DictionaryFingerprintTestCase
            {
                Title = "Json fingerprints only.",
                Fingerprints = new Dictionary<string, string>
                {
                    { "asset-v2", @"{""id"":""id"", ""part"":""part""}"},
                    { "validation-v2", @"{""id"":""id"", ""secret"":""secret""}"},
                },
                Expected = new Fingerprint
                {
                    Id = "id",
                    Part = "part",
                    Secret = "secret",
                }
            },
            new DictionaryFingerprintTestCase
            {
                Title = "Json and square brackets fingerprints.",
                Fingerprints = new Dictionary<string, string>
                {
                    { "asset-v1", "[id=id][part=part]" },
                    { "validation-v1", "[id=id][secret=secret]" },
                    { "asset-v2", @"{""id"":""id"", ""part"":""part""}"},
                    { "validation-v2", @"{""id"":""id"", ""secret"":""secret""}"},
                },
                Expected = new Fingerprint
                {
                    Id = "id",
                    Part = "part",
                    Secret = "secret",
                }
            },
            new DictionaryFingerprintTestCase
            {
                Title = "Json and square brackets fingerprints.",
                Fingerprints = new Dictionary<string, string>
                {
                    { "asset-v1", "[id=id][part=part][resource=resource[][part=]]" },
                    { "validation-v1", "[id=id][secret=secret]" },
                    { "asset-v2", @"{""id"":""id"", ""part"":""part"", ""resource"":""resource[][part=]""}"},
                    { "validation-v2", @"{""id"":""id"", ""secret"":""secret""}"},
                },
                Expected = new Fingerprint
                {
                    Id = "id",
                    Part = "part",
                    Secret = "secret",
                    Resource = "resource[][part=]"
                }
            },
        };

        private static string GetKeyNameForProperty(string propertyName)
        {
            FieldInfo fi = typeof(Fingerprint).GetField($"{propertyName}KeyName");
            return (string)fi.GetValue(null);
        }

        internal struct FingerprintTestCase
        {
            public string Title;
            public string Text;
            public Fingerprint Expected;
            public Type ExceptionType;
        }

        internal struct DictionaryFingerprintTestCase
        {
            public string Title;
            public Dictionary<string, string> Fingerprints;
            public Fingerprint Expected;
        }
    }
}
