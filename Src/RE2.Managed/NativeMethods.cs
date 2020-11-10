// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher.RE2.Managed
{
    internal static class NativeMethods
    {
        static NativeMethods()
        {
            if (Regex2.NativeLibraryFolderPath != null)
            {
                string dllName = (Environment.Is64BitProcess ? "RE2.Native.x64.dll" : "RE2.Native.x86.dll");
                string filePath = Path.Combine(Regex2.NativeLibraryFolderPath, dllName);

                if (File.Exists(filePath))
                {
                    LoadLibrary(filePath);
                }
            }
            else
            {
                string driverDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

                // Load if next to this binary
                string dllName = (Environment.Is64BitProcess ? "RE2.Native.x64.dll" : "RE2.Native.x86.dll");
                string dllAdjacent = Path.Combine(driverDirectory, dllName);
                if (File.Exists(dllAdjacent))
                {
                    LoadLibrary(dllAdjacent);
                }

                // Load if in runtimes subdirectory
                string runtimeFolder = (Environment.Is64BitProcess ? @"runtimes\win-x64\native" : @"runtimes\win-x86\native");
                string dllInRuntime = Path.Combine(driverDirectory, runtimeFolder, dllName);
                if (File.Exists(dllInRuntime))
                {
                    LoadLibrary(dllInRuntime);
                }
            }
        }

        public static int Test()
        {
            return Environment.Is64BitProcess ? NativeMethodsX64.Test() : NativeMethodsX86.Test();
        }

        public static int BuildRegex(String8Interop regex, int regexOptions)
        {
            return Environment.Is64BitProcess
                ? NativeMethodsX64.BuildRegex(regex, regexOptions)
                : NativeMethodsX86.BuildRegex(regex, regexOptions);
        }

        public static void ClearRegexes()
        {
            if (Environment.Is64BitProcess)
            {
                NativeMethodsX64.ClearRegexes();
            }
            else
            {
                NativeMethodsX86.ClearRegexes();
            }
        }

        public unsafe static int Matches(int regexIndex, String8Interop text, int fromTextIndex, Match2* matches, int matchesLength, int timeoutMilliseconds)
        {
            return Environment.Is64BitProcess
                ? NativeMethodsX64.Matches(regexIndex, text, fromTextIndex, matches, matchesLength, timeoutMilliseconds)
                : NativeMethodsX86.Matches(regexIndex, text, fromTextIndex, matches, matchesLength, timeoutMilliseconds);
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public unsafe static extern IntPtr LoadLibrary(string libraryPath);

        [DllImport("kernel32.dll")]
        public unsafe static extern void FreeLibrary(IntPtr address);

        private static class NativeMethodsX86
        {
            [DllImport("RE2.Native.x86.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl), SuppressUnmanagedCodeSecurity]
            public unsafe static extern int Test();

            [DllImport("RE2.Native.x86.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl), SuppressUnmanagedCodeSecurity]
            public unsafe static extern int BuildRegex(String8Interop regex, int regexOptions);

            [DllImport("RE2.Native.x86.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl), SuppressUnmanagedCodeSecurity]
            public unsafe static extern void ClearRegexes();

            [DllImport("RE2.Native.x86.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl), SuppressUnmanagedCodeSecurity]
            public unsafe static extern int Matches(int regexIndex, String8Interop text, int fromTextIndex, Match2* matches, int matchesLength, int timeoutMilliseconds);
        }

        private static class NativeMethodsX64
        {
            [DllImport("RE2.Native.x64.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl), SuppressUnmanagedCodeSecurity]
            public unsafe static extern int Test();

            [DllImport("RE2.Native.x64.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl), SuppressUnmanagedCodeSecurity]
            public unsafe static extern int BuildRegex(String8Interop regex, int regexOptions);

            [DllImport("RE2.Native.x64.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl), SuppressUnmanagedCodeSecurity]
            public unsafe static extern void ClearRegexes();

            [DllImport("RE2.Native.x64.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl), SuppressUnmanagedCodeSecurity]
            public unsafe static extern int Matches(int regexIndex, String8Interop text, int fromTextIndex, Match2* matches, int matchesLength, int timeoutMilliseconds);
        }
    }
}
