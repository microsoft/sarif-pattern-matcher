// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

using Microsoft.RE2.Managed;

using Sarif.PatternMatcher.Benchmark;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Benchmark.Benchmarks
{
    public class RegexManySignaturesBenchmarks : BenchmarksBase
    {
        public RegexManySignaturesBenchmarks()
        {
            Signatures = new[] {
                "SharedAccessKeyName",
                "EndpointSuffix",
                "DefaultEndpointsProtocol",
                "initial catalog",
                "Initial Catalog",
                "INITIAL CATALOG",
                "database",
                "Database",
                "DATABASE",
                "dbname",
                "DbName",
                "DBNAME",
                "AzCa",
                "ACDb",
                "AzSe",
                "AzFu",
                "8Q~",
                "7Q~",
                "ghp_",
                "npm_",
                "dapi",
                "AKIA",
                "LTAI",
                "ASIA",
                "GOOG",
                "aio_",
                "dvc_",
                "pat-",
                "ion_",
                "EZAK",
                "EZTK",
                "AKID",
                "tfp_",
                "FLWSECK-",
                "eyJrIjoi",
                "dG9rO",
                "lin_api_",
                "lin_oauth_",
                "Mid-server-",
                "NRIQ-",
                "NRAK-",
                "NRRA-",
                "_live",
                "pscale_",
                "amzn1",
                "jfrog",
                "shpat_",
                "shpss_",
                "PMAK-",
                "CLOJARS_",
                "duffel_",
                "rdme_xn8s9h",
                "rpa_",
                "samsara_api_",
                "gzUdQrDW",
                "secret_scanning",
                "xkeysib-",
                "xsmtpsib-",
                "shippo_",
                "xapp-",
                "sk_live_",
                "sys_live_",
                "zpka_",
                "_test_",
                "waka_",
                "gcntfy-",
                "persona_",

                "+ASt",
                "/AM7",
                "+ASb",
                "+AEh",
                "+ABa",
                "+AMC",
                "+ARm",
                "+ACR",
                ".office.com/webhook",
                ".core.windows.net",
                ".core.chinacloudapi.cn",
                ".core.cloudapi",
                ".azurewebsites",
                ".azureedge.net",
                ".msecnd.net",
                ".documents.azure.com",
                ".logic.azure.com",
                "hvs.",
                "dp.audit",
                "dp.pt",
                "dp.scim",
                "b.AAAAAQ",
                "hvb.AA",

                ".v1",
                "sk-",
                "SG.",
                "sk_",
                "PSK",

                "figd_",
                "figo_",
                "figu_",
                "figdr_",
                "figdh_",
                "figor_",
                "figoh_",
                "figur_",
                "figuh_",
                "pcs_",
                "pcu_",
                "wfa_",
                "wfb_",
                "wfc_",
                "wfd_",
                "wfe_",
                "wff_",
                "wfg_",
                "wfh_",
                "wfi_",
                "wfj_",
                "wfk_",
                "wfl_",
                "wfm_",
                "wfn_",
                "wfo_",
                "wfp_",
                "wfq_",
                "wfr_",
                "wfs_",
                "wft_",
                "wfu_",
                "wfv_",
                "wfw_",
                "wfx_",
                "wfy_",
                "wfz_",
                "y0-6_",
                "dp.ct",
                "dp.st",
                "CiQ",
                "CiR",
                "lma_",
                "lmb_",
                "oy2a",
                "oy2b",
                "oy2c",
                "oy2d",
                "oy2e",
                "oy2f",
                "oy2g",
                "oy2h",
                "oy2i",
                "oy2j",
                "oy2k",
                "oy2l",
                "oy2m",
                "oy2n",
                "oy2o",
                "oy2p",
                "xoxp",
                "xoxb",
                "xoxa",
                "xoxo",
                "xoxr",
                "xoxs",
                "gh1_",
                "ghp_",
                "gho_",
                "ghr_",
                "ghs_",
                "ghu_",
                "doo_v",
                "dop_v",
                "dor_v",
                "dos_v",

                // "[2-7a-z]{52}",
            };

            RegexSignatures = new[] {
                "SharedAccessKeyName",
                "EndpointSuffix",
                "DefaultEndpointsProtocol",
                "initial catalog",
                "Initial Catalog",
                "INITIAL CATALOG",
                "database",
                "Database",
                "DATABASE",
                "dbname",
                "DbName",
                "DBNAME",
                "AzCa",
                "ACDb",
                "AzSe",
                "AzFu",
                "8Q~",
                "7Q~",
                "ghp_",
                "npm_",
                "dapi",
                "AKIA",
                "LTAI",
                "ASIA",
                "GOOG",
                "aio_",
                "dvc_",
                "pat-",
                "ion_",
                "EZAK",
                "EZTK",
                "AKID",
                "tfp_",
                "FLWSECK-",
                "eyJrIjoi",
                "dG9rO",
                "lin_api_",
                "lin_oauth_",
                "Mid-server-",
                "NRIQ-",
                "NRAK-",
                "NRRA-",
                "_live",
                "pscale_",
                "amzn1",
                "jfrog",
                "shpat_",
                "shpss_",
                "PMAK-",
                "CLOJARS_",
                "duffel_",
                "rdme_xn8s9h",
                "rpa_",
                "samsara_api_",
                "gzUdQrDW",
                "secret_scanning",
                "xkeysib-",
                "xsmtpsib-",
                "shippo_",
                "xapp-",
                "sk_live_",
                "sys_live_",
                "zpka_",
                "_test_",
                "waka_",
                "gcntfy-",
                "persona_",

                "\\+ASt",
                "\\/AM7",
                "\\+ASb",
                "\\+AEh",
                "\\+ABa",
                "\\+AMC",
                "\\+ARm",
                "\\+ACR",
                "\\.office\\.com\\/webhook",
                "\\.core\\.windows\\.net",
                "\\.core\\.chinacloudapi\\.cn",
                "\\.core\\.cloudapi",
                "\\.azurewebsites",
                "\\.azureedge\\.net",
                "\\.msecnd\\.net",
                "\\.documents\\.azure\\.com",
                ".logic\\.azure\\.com",
                "hvs\\.",
                "dp\\.audit",
                "dp\\.pt",
                "dp\\.scim",
                "b\\.AAAAAQ",
                "hvb\\.AA",

                "\\b\\.v1",
                "\\bsk-",
                "\\bSG\\.",
                "\\bsk_",
                "\\bPSK",

                "fig[dou][rh]*_",
                "pc[su]_",
                "wf[a-z]_",
                "y[0-6]_",
                "dp\\.[cs]t",
                "\\bCi[QR]",
                "lm[ab]_",
                "oy2[a-p]",
                "xox[pbaors]",
                "gh[1porsu]_",
                "do[oprs]_v",

                "[2-7a-z]{52}",
            };

            RegexSignature = String.Join("|", RegexSignatures);

            AdoPatChars = new HashSet<char>() {
                '2',
                '3',
                '4',
                '5',
                '6',
                '7',
                'a',
                'b',
                'c',
                'd',
                'e',
                'f',
                'g',
                'h',
                'i',
                'j',
                'k',
                'l',
                'm',
                'n',
                'o',
                'p',
                'q',
                'r',
                's',
                't',
                'u',
                'v',
                'w',
                'x',
                'y',
                'z',
            };
        }

        private string[] Signatures { get; set; }
        private string[] RegexSignatures { get; set; }
        private string RegexSignature { get; set; }
        private string DotNetRegexPattern { get; set; }

        private HashSet<char> AdoPatChars;

        [Params(1)]
        public int ScanTargetSizeInKilobytes;

        [Params(false)]
        public virtual bool FindAllMatches { get; set; }

        [Params(false)]
        public virtual bool IncludeSignatureInTargetContents { get; set; }

        public virtual bool PrintMatchCount { get; set; }

        [Params(true, false)]
        public virtual bool UseSyntheticContent { get; set; }

        protected Dictionary<string, string> TargetContents;

        public int Run(RegexManySignaturesOptions _)
        {
            if (!Debugger.IsAttached)
            {
                BenchmarkRunner.Run<RegexManySignaturesBenchmarks>();
            }
            else
            {
                new RegexManySignaturesBenchmarks()
                {
                    FindAllMatches = true,
                    TargetContents = new Dictionary<string, string>() { { "synthetic.txt", GenerateScanTarget(1, false) } },
                }.IndexOf();
            }
            return 0;
        }

        [GlobalSetup]
        public void Setup()
        {
            TargetContents = new Dictionary<string, string>();

            if (UseSyntheticContent)
            {
                TargetContents.Add("synthetic.txt", GenerateScanTarget(ScanTargetSizeInKilobytes, IncludeSignatureInTargetContents));
            }
            else
            {
                // var sourceDirectory = @"D:\vso\src\DevSecOps\";
                var sourceDirectory = @"D:\ConfigChange\src\Governance";
                foreach (var file in Directory.EnumerateFiles(sourceDirectory, "*.*", SearchOption.AllDirectories))
                {
                    TargetContents.Add(file, File.ReadAllText(file));
                }
            }

            Console.WriteLine($"Verifying {TargetContents.Count} files");
            int totalSize = 0;
            foreach (var contentKvp in TargetContents)
            {
                var content = contentKvp.Value;
                totalSize += content.Length;
                Console.WriteLine($"{contentKvp.Key} {nameof(IndexOfInternal)}        {IndexOfInternal(content)}");
                Console.WriteLine($"{contentKvp.Key} {nameof(RE2RegexEngineInternal)} {RE2RegexEngineInternal(content)}");
            }

            Console.WriteLine($"Total size {totalSize * 2:#,##0} bytes");
        }

        [Benchmark]
        public void IndexOf()
        {
            foreach (var content in TargetContents)
            {
                IndexOfInternal(content.Value);
            }
        }

        private int IndexOfInternal(string content)
        {
            int count = 0;
            foreach (string signature in Signatures)
            {
                int maxLength = content.Length;
                int index = 0;

                if (FindAllMatches)
                {
                    // while (index != -1 && index < maxLength)
                    // {
                    //     index = content.IndexOf(signature, index + signature.Length, StringComparison.Ordinal);
                    //     count++;
                    // }
                }
                else
                {
                    index = content.IndexOf(signature, StringComparison.Ordinal);

                    if (index >= 0)
                    {
                        count++;
                        break;
                    }
                }
            }

            if (FindAllMatches)
            {
                int maxLength = content.Length;
                int index = 0;

                    while (index != -1 && index < maxLength)
                    {
                        index = AdoPatIndexOf(content, index + 52);
                        count++;
                    }
            }
            else if (count == 0)
            {
                var index = AdoPatIndexOf(content);

                if (index >= 0)
                {
                    count++;
                }
            }

            if (PrintMatchCount)
            {
                Console.WriteLine($"count={count}");
            }

            return count;
        }

        private int AdoPatIndexOf(string content, int startIndex = 0)
        {
            int consecutiveChars = 0;
            int maxConsecutiveChars = 52;

            int length = content.Length;
            for (int i = startIndex; i < length; i++)
            {
                if (AdoPatChars.Contains(content[i]))
                {
                    consecutiveChars++;
                    if (consecutiveChars >= maxConsecutiveChars)
                    {
                        return i - maxConsecutiveChars;
                    }
                }
                else
                {
                    consecutiveChars = 0;
                }
            }

            return -1;
        }

        // [Benchmark]
        public virtual void DotNetRegexEngine()
        {
            foreach (var content in TargetContents)
            {
                DotNetRegexEngineInternal(content.Value);
            }
        }

        private int DotNetRegexEngineInternal(string content)
        {
            int count = 0;
            if (FindAllMatches)
            {
                foreach (FlexMatch match in DotNetRegex.Instance.Matches(content, RegexSignature))
                {
                    count++;
                }
            }
            else
            {
                if (DotNetRegex.Instance.IsMatch(content, RegexSignature))
                {
                    count++;
                }
            }

            if (PrintMatchCount)
            {
                Console.WriteLine($"count={count}");
            }

            return count;
        }

        // [Benchmark]
        public void CachedDotNetEngine()
        {
            foreach (var content in TargetContents)
            {
                CachedDotNetEngineInternal(content.Value);
            }
        }

        private int CachedDotNetEngineInternal(string content)
        {
            int count = 0;
            if (FindAllMatches)
            {
                foreach (FlexMatch match in CachedDotNetRegex.Instance.Matches(content, RegexSignature))
                {
                    count++;
                }
            }
            else
            {
                if (CachedDotNetRegex.Instance.IsMatch(content, RegexSignature))
                {
                    count++;
                }

            }

            if (PrintMatchCount)
            {
                Console.WriteLine($"count={count}");
            }

            return count;
        }

        [Benchmark]
        public void RE2RegexEngine()
        {
            foreach (var content in TargetContents)
            {
                RE2RegexEngineInternal(content.Value);
            }
        }

        private int RE2RegexEngineInternal(string content)
        {
            int count = 0;
            if (FindAllMatches)
            {
                foreach (FlexMatch match in RE2Regex.Instance.Matches(content, RegexSignature))
                {
                    count++;
                }
            }
            else
            {
                if (RE2Regex.Instance.IsMatch(content, RegexSignature))
                {
                    count++;
                }
            }

            if (PrintMatchCount)
            {
                Console.WriteLine($"count={count}");
            }

            return count;
        }

        // [Benchmark]
        // public void IronRE2Engine()
        // {
        //     int count = 0;
        //     if (FindAllMatches)
        //     {
        //         foreach (FlexMatch match in IronRE2Regex.Instance.Matches(TargetContents, RegexSignature))
        //         {
        //             count++;
        //         }
        //     }
        //     else
        //     {
        //         IronRE2Regex.Instance.IsMatch(TargetContents, RegexSignature);
        //     }
        // }

        private string GenerateScanTarget(int sizeInMegabytes, bool includeSignature)
        {
            for (int i = 0; i < 10; i++)
            {
                var target = GenerateScanTargetInternal(sizeInMegabytes, includeSignature);

                if (IncludeSignatureInTargetContents)
                {
                    return target;
                }
                else if ((RE2RegexEngineInternal(target) == 0) && (IndexOfInternal(target) == 0))
                {
                    return target;
                }

                Console.WriteLine("Generated target contents did not meet the criteria. Regenerating file.");
            }

            throw new InvalidOperationException($"Could not generate scan target that satisfied the criteria.");
        }

        private string GenerateScanTargetInternal(int sizeInMegabytes, bool includeSignature)
        {
            var sb = new StringBuilder();

            int size = sizeInMegabytes * 1024;

            while (sb.Length < size)
            {
                sb.Append($"{Guid.NewGuid()} {(includeSignature ? Signatures[DateTime.Now.Ticks % Signatures.Length] : "")} ");
            }

            return sb.ToString();
        }
    }
}
