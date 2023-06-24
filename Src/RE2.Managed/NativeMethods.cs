// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;

namespace Microsoft.RE2.Managed
{
    internal static class NativeMethods
    {
        static NativeMethods()
        {
            string platform =
                RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "win" : "linux";

            bool isWindows = platform == "win";

            // Strictly speaking we don't need any platform-specific code here. I leave
            // it just in case we find out that we *do* need to perform the Linux
            // equivalent of LoadLibrary to get everything to work.
            string dllName = RuntimeInformation.IsOSPlatform(OSPlatform.Linux)
                ? "libcre2.so"
                : Environment.Is64BitProcess ? "RE2.Native.x64.dll" : "RE2.Native.x86.dll";

            if (Regex2.NativeLibraryFolderPath != null)
            {
                string filePath = Path.Combine(Regex2.NativeLibraryFolderPath, dllName);

                if (File.Exists(filePath))
                {
                    if (isWindows) { LoadLibrary(filePath); } else { LinuxMethods.dlopen(filePath, LinuxMethods.RTLD_NOW); }
                }
            }
            else
            {
                string driverDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

                // Load if next to this binary
                string dllAdjacent = Path.Combine(driverDirectory, dllName);
                if (File.Exists(dllAdjacent))
                {
                    if (isWindows) { LoadLibrary(dllAdjacent); } else { LinuxMethods.dlopen(dllAdjacent, LinuxMethods.RTLD_NOW); }
                }

                // Load if in runtimes subdirectory
                string runtimeFolder = Environment.Is64BitProcess ? @$"runtimes\{platform}-x64\native" : @$"runtimes\{platform}-x86\native";
                string dllInRuntime = Path.Combine(driverDirectory, runtimeFolder, dllName);
                if (File.Exists(dllInRuntime))
                {
                    if (isWindows) { LoadLibrary(dllInRuntime); } else { LinuxMethods.dlopen(dllInRuntime, LinuxMethods.RTLD_NOW); }
                }
            }
        }

        public static int Test()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return LinuxMethods.Test();
            }

            return Environment.Is64BitProcess ? NativeMethodsX64.Test() : NativeMethodsX86.Test();
        }

        public static int BuildRegex(String8Interop regex, int regexOptions, long maxMemoryInBytes)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return LinuxMethods.BuildRegex(regex, regexOptions, maxMemoryInBytes);
            }

            return Environment.Is64BitProcess
                ? NativeMethodsX64.BuildRegex(regex, regexOptions, maxMemoryInBytes)
                : NativeMethodsX86.BuildRegex(regex, regexOptions, maxMemoryInBytes);
        }

        public static void ClearRegexes()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                LinuxMethods.ClearRegexes();
            }
            else if (Environment.Is64BitProcess)
            {
                NativeMethodsX64.ClearRegexes();
            }
            else
            {
                NativeMethodsX86.ClearRegexes();
            }
        }

        public static unsafe int Matches(int regexIndex, String8Interop text, int fromTextIndex, Match2* matches, int matchesLength, int timeoutMilliseconds)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return LinuxMethods.Matches(regexIndex, text, fromTextIndex, matches, matchesLength, timeoutMilliseconds);
            }

            return Environment.Is64BitProcess
                ? NativeMethodsX64.Matches(regexIndex, text, fromTextIndex, matches, matchesLength, timeoutMilliseconds)
                : NativeMethodsX86.Matches(regexIndex, text, fromTextIndex, matches, matchesLength, timeoutMilliseconds);
        }

        public static unsafe void MatchesCaptureGroups(int regexIndex, String8Interop text, MatchesCaptureGroupsOutput** matchesCaptureGroupsOutput)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                LinuxMethods.MatchesCaptureGroups(regexIndex, text, matchesCaptureGroupsOutput);
            }
            else if (Environment.Is64BitProcess)
            {
                NativeMethodsX64.MatchesCaptureGroups(regexIndex, text, matchesCaptureGroupsOutput);
            }
            else
            {
                NativeMethodsX86.MatchesCaptureGroups(regexIndex, text, matchesCaptureGroupsOutput);
            }
        }

        public static unsafe void MatchesCaptureGroupsDispose(MatchesCaptureGroupsOutput* matchesCaptureGroupsOutput)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                LinuxMethods.MatchesCaptureGroupsDispose(matchesCaptureGroupsOutput);
            }
            else if (Environment.Is64BitProcess)
            {
                NativeMethodsX64.MatchesCaptureGroupsDispose(matchesCaptureGroupsOutput);
            }
            else
            {
                NativeMethodsX86.MatchesCaptureGroupsDispose(matchesCaptureGroupsOutput);
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static unsafe extern IntPtr LoadLibrary(string libraryPath);

        [DllImport("kernel32.dll")]
        public static unsafe extern void FreeLibrary(IntPtr address);

        private static class LinuxMethods
        {
            public const int RTLD_NOW = 0x002;

            [SuppressUnmanagedCodeSecurity]
            [DllImport("libdl.so.2", ExactSpelling = true)]
            public static unsafe extern IntPtr dlopen(string fileName, int flags);

            [SuppressUnmanagedCodeSecurity]
            [DllImport("libcre2.so", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern int Test();

            [SuppressUnmanagedCodeSecurity]
            [DllImport("libcre2.so", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern int BuildRegex(String8Interop regex, int regexOptions, long maxMemoryInBytes);

            [SuppressUnmanagedCodeSecurity]
            [DllImport("libcre2.so", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern void ClearRegexes();

            [SuppressUnmanagedCodeSecurity]
            [DllImport("libcre2.so", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern int Matches(int regexIndex, String8Interop text, int fromTextIndex, Match2* matches, int matchesLength, int timeoutMilliseconds);

            [SuppressUnmanagedCodeSecurity]
            [DllImport("libcre2.so", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern bool MatchesCaptureGroups(int regexIndex, String8Interop text, MatchesCaptureGroupsOutput** matchesCaptureGroupsOutput);

            [SuppressUnmanagedCodeSecurity]
            [DllImport("libcre2.so", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern bool MatchesCaptureGroupsDispose(MatchesCaptureGroupsOutput* matchesCaptureGroupsOutput);
        }

        private static class NativeMethodsX86
        {
            [SuppressUnmanagedCodeSecurity]
            [DllImport("RE2.Native.x86.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern int Test();

            [SuppressUnmanagedCodeSecurity]
            [DllImport("RE2.Native.x86.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern int BuildRegex(String8Interop regex, int regexOptions, long maxMemoryInBytes);

            [SuppressUnmanagedCodeSecurity]
            [DllImport("RE2.Native.x86.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern void ClearRegexes();

            [SuppressUnmanagedCodeSecurity]
            [DllImport("RE2.Native.x86.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern int Matches(int regexIndex, String8Interop text, int fromTextIndex, Match2* matches, int matchesLength, int timeoutMilliseconds);

            [SuppressUnmanagedCodeSecurity]
            [DllImport("RE2.Native.x86.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern bool MatchesCaptureGroups(int regexIndex, String8Interop text, MatchesCaptureGroupsOutput** matchesCaptureGroupsOutput);

            [SuppressUnmanagedCodeSecurity]
            [DllImport("RE2.Native.x86.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern bool MatchesCaptureGroupsDispose(MatchesCaptureGroupsOutput* matchesCaptureGroupsOutput);
        }

        private static class NativeMethodsX64
        {
            [SuppressUnmanagedCodeSecurity]
            [DllImport("RE2.Native.x64.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern int Test();

            [SuppressUnmanagedCodeSecurity]
            [DllImport("RE2.Native.x64.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern int BuildRegex(String8Interop regex, int regexOptions, long maxMemoryInBytes);

            [SuppressUnmanagedCodeSecurity]
            [DllImport("RE2.Native.x64.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern void ClearRegexes();

            [SuppressUnmanagedCodeSecurity]
            [DllImport("RE2.Native.x64.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern int Matches(int regexIndex, String8Interop text, int fromTextIndex, Match2* matches, int matchesLength, int timeoutMilliseconds);

            [SuppressUnmanagedCodeSecurity]
            [DllImport("RE2.Native.x64.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern bool MatchesCaptureGroups(int regexIndex, String8Interop text, MatchesCaptureGroupsOutput** matchesCaptureGroupsOutput);

            [SuppressUnmanagedCodeSecurity]
            [DllImport("RE2.Native.x64.dll", PreserveSig = true, CallingConvention = CallingConvention.Cdecl)]
            public static unsafe extern bool MatchesCaptureGroupsDispose(MatchesCaptureGroupsOutput* matchesCaptureGroupsOutput);
        }
    }
}
