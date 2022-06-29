// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

using CommandLine;

using FluentAssertions;

using Kusto.Cloud.Platform.Utils;

using Microsoft.CodeAnalysis.Sarif.Driver;

using Moq;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    public class ProgramTests
    {
        [Fact]
        public void Program_ResponseFileWorksWithNoExplicitlyAllocatedFileSystem()
        {
            string responseFilePath = $"@{Guid.NewGuid()}.rsp";

            // Explicitly clear the file system object, in case an
            // out-of-order test execution has set it to a mocked object.
            Program.FileSystem = null;

            string[] args = new[] { responseFilePath };
            int result = Program.Main(args);
            result.Should().Be(1);

            // These conditions indicate that the response file argument was
            // successfully processed by the command-line argument parsers 
            // and the response file was not found. This closes a very narrow
            // code path in tests where an uninstantiated FileSystem object
            // causes a null dereference. All other tests for this area provide
            // a non-null file system object instance.
            Program.RuntimeException.Should().NotBeNull();
            Program.RuntimeException.GetType().Should().Be(typeof(FileNotFoundException));
        }

        [Fact]
        public void Program_ResponseFileWorks()
        {
            // Ensure that simple commands, such as help and version
            // work properly (as evident by a success response code).
            TestResponseFile(new string[] { "help" });
            TestResponseFile(new string[] { "version" });

            // Our mocking strategy assumes that a single mocked called to File.ReadAllLines
            // returns the response file contents. To validate this assumptions, we'll 
            // force a failure case to prove that the previous successes are valid.
            TestResponseFile(new string[] { Guid.NewGuid().ToString() }, CommandBase.FAILURE);
        }

        [Fact]
        public void Program_ResponseFileHelpCommandWorksForAllVerbs()
        {
            // Crawl all types looking for command verbs and ensure that each one of
            // them is a valid argument to include in a response file.
            foreach (string verbName in GetVerbNames())
            {
                TestResponseFile(new string[] { $"help {verbName}" });
            }

            // Explicitly provoke a failure to build confidence in prior
            // successful tests.
            TestResponseFile(
                new string[] { $"help {Guid.NewGuid()}" }, CommandBase.FAILURE);
        }

        [Fact]
        public void Program_ResponseFileMultilineHelpCommandWorksForAllVerbs()
        {
            // Crawl all types looking for command verbs and ensure that each one of
            // them is a valid argument to include in a response file.
            foreach (string verbName in GetVerbNames())
            {
                TestResponseFile(new string[] { "help", verbName });
            }

            // Explicitly provoke a failure to build confidence in prior
            // successful tests.
            TestResponseFile(
                new string[] { $"help {Guid.NewGuid()}" }, CommandBase.FAILURE);
        }

        [Fact]
        public void Program_VerbListIsExpected()
        {
            string[] actual = GetVerbNames().ToArray();
            Array.Sort(actual);

            // Keep these in sorted order.
            string[] expected = new string[]
            {
                "analyze",
                "analyze-database",
                "export-rules",
                "export-search-definitions",
                "import-analyze",
            };

            actual.Should().BeEquivalentTo(expected);
        }

        private static void TestResponseFile(string[] responseFileContents,
                                             int expectedResult = CommandBase.SUCCESS)
        {
            string responseFilePath = "@ResponseFile.rsp";

            var mockFileSystem = new Mock<IFileSystem>();

            // Returns the mocked response file contents.
            mockFileSystem.Setup(x => x.FileReadAllLines(It.IsAny<string>()))
                .Returns<string>((path) =>
                {
                    return responseFileContents;
                });

            Program.FileSystem = mockFileSystem.Object;

            string[] args = new[] { responseFilePath };
            string flattenedResponseFile = string.Join(' ', responseFileContents);
            int result = Program.Main(args);

            result.Should().Be(
                expectedResult,
                $"response files consisted of '{flattenedResponseFile}'");
        }

        private static IList<string> GetVerbNames()
        {
            var verbNames = new List<string>();

            Assembly assembly = typeof(Program).Assembly;
            foreach (Type type in assembly.GetTypes())
            {
                VerbAttribute verbAttribute = type.GetCustomAttribute<VerbAttribute>();
                if (verbAttribute == null) { continue; }

                verbNames.Add(verbAttribute.Name);
            }

            // We pick up this verb from the driver framework.
            verbNames.Add("analyze");

            return verbNames;
        }
    }
}
