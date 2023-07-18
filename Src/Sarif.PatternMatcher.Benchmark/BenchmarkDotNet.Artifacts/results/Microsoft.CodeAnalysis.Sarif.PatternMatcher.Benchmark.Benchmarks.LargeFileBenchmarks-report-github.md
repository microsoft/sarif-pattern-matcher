``` ini

BenchmarkDotNet=v0.12.1, OS=Windows 10.0.22621
Intel Core i9-10980XE CPU 3.00GHz, 1 CPU, 36 logical and 18 physical cores
  [Host]     : .NET Framework 4.8 (4.8.9166.0), X64 RyuJIT
  DefaultJob : .NET Framework 4.8 (4.8.9166.0), X64 RyuJIT


```
|                                         Method | scanTargetSizeInMegabytes |     Mean |   Error |  StdDev |      Gen 0 | Gen 1 | Gen 2 | Allocated |
|----------------------------------------------- |-------------------------- |---------:|--------:|--------:|-----------:|------:|------:|----------:|
| AnalyzeCommand_SimpleAnalysisCachedDotNetRegex |                        10 | 257.6 ms | 5.14 ms | 5.50 ms | 51000.0000 |     - |     - | 311.43 MB |
|               AnalyzeCommand_SimpleAnalysisRE2 |                        10 | 248.8 ms | 4.85 ms | 4.54 ms | 49000.0000 |     - |     - | 295.69 MB |
