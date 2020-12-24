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
[assembly: InternalsVisibleTo("Test.UnitTests.String8, PublicKey=0024000004800000940000000602000000240000525341310004000001000100433fbf156abe9718142bdbd48a440e779a1b708fd21486ee0ae536f4c548edf8a7185c1e3ac89ceef76c15b8cc2497906798779a59402f9b9e27281fb15e7111566cdc9a9f8326301d45320623c5222089cf4d0013f365ae729fb0a9c9d15138042825cd511a0f3d4887a7b92f4c2749f81b410813d297b73244cf64995effb1")]
[assembly: InternalsVisibleTo("Test.UnitTests.RE2.Managed, PublicKey=0024000004800000940000000602000000240000525341310004000001000100433fbf156abe9718142bdbd48a440e779a1b708fd21486ee0ae536f4c548edf8a7185c1e3ac89ceef76c15b8cc2497906798779a59402f9b9e27281fb15e7111566cdc9a9f8326301d45320623c5222089cf4d0013f365ae729fb0a9c9d15138042825cd511a0f3d4887a7b92f4c2749f81b410813d297b73244cf64995effb1")]
[assembly: InternalsVisibleTo("Test.UnitTests.Sarif.PatternMatcher, PublicKey=0024000004800000940000000602000000240000525341310004000001000100433fbf156abe9718142bdbd48a440e779a1b708fd21486ee0ae536f4c548edf8a7185c1e3ac89ceef76c15b8cc2497906798779a59402f9b9e27281fb15e7111566cdc9a9f8326301d45320623c5222089cf4d0013f365ae729fb0a9c9d15138042825cd511a0f3d4887a7b92f4c2749f81b410813d297b73244cf64995effb1")]
[assembly: InternalsVisibleTo("Test.UnitTests.Sarif.PatternMatcher.Cli, PublicKey=0024000004800000940000000602000000240000525341310004000001000100433fbf156abe9718142bdbd48a440e779a1b708fd21486ee0ae536f4c548edf8a7185c1e3ac89ceef76c15b8cc2497906798779a59402f9b9e27281fb15e7111566cdc9a9f8326301d45320623c5222089cf4d0013f365ae729fb0a9c9d15138042825cd511a0f3d4887a7b92f4c2749f81b410813d297b73244cf64995effb1")]
