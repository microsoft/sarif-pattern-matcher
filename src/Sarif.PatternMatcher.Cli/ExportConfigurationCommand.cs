// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Reflection;

using Microsoft.CodeAnalysis.Sarif.Driver;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Cli
{
    internal class ExportConfigurationCommand : ExportConfigurationCommandBase
    {
        public override IOptionsProvider AdditionalOptionsProvider => new AnalyzeContext();

        public override IEnumerable<Assembly> DefaultPluginAssemblies { get => new List<Assembly>(); set => base.DefaultPluginAssemblies = value; }

        public override int Run(ExportConfigurationOptions exportOptions)
        {
            return base.Run(exportOptions);
        }
    }
}
