// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

using FluentAssertions;

using Xunit;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    public class ExportRulesMetatadaCommandTests
    {
        [Fact]
        public void ExportRulesMetatadaCommand_InvalidOptions()
        {
            var tests = new[]
            {
                new
                {
                    Options = (ExportRulesMetatadaOptions)null
                },
                new
                {
                    Options = new ExportRulesMetatadaOptions()
                },
                new
                {
                    Options = new ExportRulesMetatadaOptions
                    {
                        SearchDefinitionsPaths = new List<string>
                        {
                            $@"C:\{Guid.NewGuid()}.txt"
                        }
                    }
                }
            };

            foreach (var test in tests)
            {
                var command = new ExportRulesMetatadaCommand();
                int result = command.Run(test.Options);
                result.Should().Be(1);
            }
        }
    }
}
