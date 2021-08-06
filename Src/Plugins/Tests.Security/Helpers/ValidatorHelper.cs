// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Reflection;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Helpers
{
    public static class ValidatorHelper
    {
        /// <summary>
        /// ResetStaticInstance is a method that will invoke the static instance creation.
        /// This is required if we are injecting HttpClient, for example.
        /// </summary>
        /// <typeparam name="T">The class you want to reset.</typeparam>
        public static void ResetStaticInstance<T>()
        {
            ConstructorInfo constructor = typeof(T).GetConstructor(BindingFlags.Static | BindingFlags.NonPublic, null, new Type[0], null);
            constructor.Invoke(null, null);
        }
    }
}
