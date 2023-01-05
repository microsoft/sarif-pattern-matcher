// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: ComVisible(false)]
[assembly: CLSCompliant(false)]
[assembly: NeutralResourcesLanguage("en-US", UltimateResourceFallbackLocation.MainAssembly)]

// This reference necessary for the MOQ test engine.
[assembly: InternalsVisibleTo("DynamicProxyGenAssembly2, PublicKey=0024000004800000940000000602000000240000525341310004000001000100c547cac37abd99c8db225ef2f6c8a3602f3b3606cc9891605d02baa56104f4cfc0734aa39b93bf7852f7d9266654753cc297e7d2edfe0bac1cdcf9f717241550e0a7b191195b7667bb4f64bcb8e2121380fd1d9d46ad2d92d2d15605093924cceaf74c4861eff62abf69b9291ed0a340e113be11e6a7d3113e92484cf7045cc7")]

// By default, we expose all internal product data to test binaries
[assembly: InternalsVisibleTo("Test.UnitTests.String8")]
[assembly: InternalsVisibleTo("Test.UnitTests.RE2.Managed")]
[assembly: InternalsVisibleTo("Test.UnitTests.Sarif.PatternMatcher")]
[assembly: InternalsVisibleTo("Test.UnitTests.Sarif.PatternMatcher.Cli")]
[assembly: InternalsVisibleTo("Test.UnitTests.Sarif.PatternMatcher.Sdk")]
[assembly: InternalsVisibleTo("Tests.Security")]
[assembly: InternalsVisibleTo("Tests.Security.Internal")]
[assembly: InternalsVisibleTo("Tests.AzureDevOpsConfiguration")]
[assembly: InternalsVisibleTo("Tests.Security.PushProtection")]
