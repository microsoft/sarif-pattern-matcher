# Release History

## Definitions
- NR  => New rule.
- DEP => Update dependency.
- BRK => General breaking change.
- BUG => General bug fix.
- NEW -> New feature.
- PRF => Performance work.
- FCR => Fingerprint change or refactor.
- RRR => Rule rename or refactor.
- FPC => Regex candidate reduction.
- FNC => Regex candidate increase.
- FPS => False positive reduction in static analysis.
- FNS => False negative reduction in static analysis.
- FPD => False positive reduction in dynamic analysis.
- FND => False negative reduction in dynamic analysis.
- UER => Eliminate unhandled exceptions in rule.
- UEE => Eliminate unhandled exceptions in engine.

## v4.5.1 5/31/2023
- DEP: Update SARIF SDK submodule from [441fa8b to dd8b7b8](https://github.com/microsoft/sarif-sdk/compare/441fa8b..dd8b7b8). [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/dd8b7b8/ReleaseHistory.md). Additional eventing work.

## v4.5.0 5/16/2023
- DEP: Update SARIF SDK submodule from [51ae42 to 441fa8b](https://github.com/microsoft/sarif-sdk/compare/51ae42..441fa8b). [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/441fa8b/ReleaseHistory.md). Adds version control provenance.
- NEW: Added ETW event tracing support.

## v4.4.1 5/9/2023
- BRK: Disable `SEC101/047.CratesApiKey`. Current dynamic validator returns status code 200 to all tokens. No API endpoint seems to return different status codes to distinguish between valid and invalid API Keys
- NEW: Provide new `AnalyzeContext.SniffRegex` property that applies a pre-filter contents regex to all scan targets, when configured. https://github.com/microsoft/sarif-pattern-matcher/pull/756

## v4.3.10 04/19/2023
- DEP: Update SARIF SDK submodule from [36b4792 to 51ae42](https://github.com/microsoft/sarif-sdk/compare/36b4792..51ae42). [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/51ae42/ReleaseHistory.md).
- NEW: Added `QueryString` property to Fingerprint. [#751](https://github.com/microsoft/sarif-pattern-matcher/pull/751)

## v4.3.9 04/13/2023
- DEP: Update SARIF SDK submodule from [1ff3956 to 36b4792](https://github.com/microsoft/sarif-sdk/compare/1ff3956..36b4792). [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/36b4792/ReleaseHistory.md). Adds version control provenance.
- NEW: All `AnalyzeContext` parameters can now be expressed as XML configuration. [#750](https://github.com/microsoft/sarif-pattern-matcher/pull/750)
- BUG: We now report the anonymized base64-encoded secret (rather than it decoded form) for rules like `SEC101/102.AdoPat` with this support. [#750](https://github.com/microsoft/sarif-pattern-matcher/pull/750)
- BUG: Remove unnecessary `Test.Utilities.Sarif` reference from `Sarif.PatternMatcher` project. This test binary isn't built into our tool NuGet package and the erroneous reference causes missing file messages in some contexts. [#749](https://github.com/microsoft/sarif-pattern-matcher/pull/749)

## v4.3.8 Released 04/06/2023
- BRK: `ValidationResult` constructor now sets `ValidationState` to `Unknown`. [#733](https://github.com/microsoft/sarif-pattern-matcher/pull/733)
- BRK: `ValidatorBase.ReturnUnhandledException` now requires an `asset` parameter. [#736](https://github.com/microsoft/sarif-pattern-matcher/pull/736)
- BUG: Consistently report asset data (which may be the truncated secret) when reporting unhandled exceptions in dynamic validators. [#736](https://github.com/microsoft/sarif-pattern-matcher/pull/736)
- BUG: Properly report command-line help rather than raising `IndexOutOfRangeException` when invoking tool with no arguments. [#743](https://github.com/microsoft/sarif-pattern-matcher/pull/743)
- BUG: We do not flow `--redact-secrets` argument properly to analysis. [#746](https://github.com/microsoft/sarif-pattern-matcher/pull/746)
- NEW: All secret detecting rules now provide a `sarif/uiLabel` value in the property bag that represents a human-readable UX label for the check. [#743](https://github.com/microsoft/sarif-pattern-matcher/pull/743)
- NEW: All `AnalyzeOptions` properties now settable. [#746](https://github.com/microsoft/sarif-pattern-matcher/pull/746)

## v4.3.7 Released 03/22/2023
- DEP: Update SARIF SDK submodule from [53b0246 to 1ff3956](https://github.com/microsoft/sarif-sdk/compare/53b0246..1ff3956). [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/1ff3956/src/ReleaseHistory.md). Adds version control provenance.
- BRK: SARIF SDK update changes `--automationId` and `--automationGuid` command-line arguments to `--automation-id` and `--automation-guid`. [#732](https://github.com/microsoft/sarif-pattern-matcher/pull/732)
- BRK: `--search-definitions`/`-s` argument deprecated in favor of `plugin`/`-p`. [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/6c5825c/src/ReleaseHistory.md). Adds version control provenance.
- BUG: Resolve bug where console failed to emit `Note` messages. [#732](https://github.com/microsoft/sarif-pattern-matcher/pull/732)

## v4.3.5 Released 03/21/2023
- DEP: Update SARIF SDK submodule from [39ea626 to 53b0246](https://github.com/microsoft/sarif-sdk/compare/39ea626..53b0246). [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/53b0246/src/ReleaseHistory.md). Adds version control provenance.
- BRK: `AnalyzeOptions` `DynamicValidation`, `DisableDynamicValidationCaching`, `EnhancedReporting`, `Retry` and `RedactSecrets` properties are now `bool?'. [#727](https://github.com/microsoft/sarif-pattern-matcher/pull/727)
- BRK: Obsolete `--file-size-in-kb` argument removed. [#727](https://github.com/microsoft/sarif-pattern-matcher/pull/727)
- RRR: Updated `SEC101/016.StripeApiKey` rule to only handle live standard keys. Moved live restricted keys and test standard/restricted keys to new rules. [#721](https://github.com/microsoft/sarif-pattern-matcher/pull/721)
- FPC: Updated `SEC101/016.StripeApiKey` regular expression to only consider keys with random part of length 24, 34, or 99+. [#721](https://github.com/microsoft/sarif-pattern-matcher/pull/721)
- NR : Added `SEC101/051.StripeTestApiKey` rule with dynamic validation. [#721](https://github.com/microsoft/sarif-pattern-matcher/pull/721)
- NR : Added `SEC101/052.StripeLiveRestrictedApiKey` rule with dynamic validation. [#721](https://github.com/microsoft/sarif-pattern-matcher/pull/721)
- NR : Added `SEC101/053.StripeTestRestrictedApiKey` rule with dynamic validation. [#721](https://github.com/microsoft/sarif-pattern-matcher/pull/721)

## v4.3.3 Released 03/16/2023
- BUG: JSON logical location `fullyQualifiedName` properties incorrect when scan returns results in a different order than they occur in the file. [#726](https://github.com/microsoft/sarif-pattern-matcher/pull/726)

## v4.3.2 Released 03/15/2023
- BRK: Remove `AnalyzeContext.FileRegionsCache` property. The cache is now produced and managed by the scan engine. [#725](https://github.com/microsoft/sarif-pattern-matcher/pull/725)
- DEP: Update SARIF SDK submodule from [98d2d25 to 39ea626](https://github.com/microsoft/sarif-sdk/compare/98d2d25..39ea626). [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/39ea626/src/ReleaseHistory.md).

## v4.3.1 Released 03/14/2023
- DEP: Update SARIF SDK submodule from [420fe9c to 98d2d25](https://github.com/microsoft/sarif-sdk/compare/420fe9c..98d2d25). [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/420fe9c/src/ReleaseHistory.md).
- DEP: Remove MongoDB.Driver from `Security`.
- DEP: Update `System.Data.SqlClient` from 4.7.0 to 4.8.5. [#698](https://github.com/microsoft/sarif-pattern-matcher/pull/698)
- NEW: Add `ContainsDigitAndLetter`, `ContainsLowercaseAndUppercaseLetter` and other text evaluation functions to `ExtensionMethods`. [#722](https://github.com/microsoft/sarif-pattern-matcher/pull/722)
- BUG: Various fixes to allow for in-memory analysis and logging.

## v4.2.0 Released 03/07/2023
- DEP: Update SARIF SDK submodule from [2f79183 to 420fe9c](https://github.com/microsoft/sarif-sdk/compare/2f79183..420fe9c). [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/420fe9c/src/ReleaseHistory.md).
- BUG: Dependency update above resolve an issue where `IAnalysisLogger.AnalyzeTarget` callbacks did not occur.

## v4.1.0 Released 03/01/2023
- DEP: Update SARIF SDK submodule from [615a31a to 2f79183](https://github.com/microsoft/sarif-sdk/compare/615a31a..2f79183). [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/2f79183/src/ReleaseHistory.md).

## v4.0.0 Released 02/28/2023
- BRK: This change switches to a new, highly-context driven API provided by the SARIF driver framework.
- DEP: Update SARIF SDK submodule from [ec93dcc to 615a31a](https://github.com/microsoft/sarif-sdk/compare/ec93dcc..615a31a). [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/615a31a/src/ReleaseHistory.md).
- BUG: Eliminate `IndexOutOfRangeException` error invoking `Sarif.PatternMatcher.Cli.exe` with no arguments.
- Re-enable `SEC101/029.AlibabaCloudCredentials` in `Security` removing AlibabaCloud SDK reference.
- FPS: Eliminate `SEC101/047.CratesApiKey` false positives due to bad prefix regex pattern. [#713](https://github.com/microsoft/sarif-pattern-matcher/pull/713)

## v3.0.2 Released 02/14/2023
- Update SARIF SDK submodule from [fdb2545 to ec93dcc](https://github.com/microsoft/sarif-sdk/compare/fdb2545..ec93dcc). [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/ec93dcc/src/ReleaseHistory.md).

## v3.0.0 Released 02/02/2023
- DEP: Update SARIF SDK submodule from [24c773b to fdb2545](https://github.com/microsoft/sarif-sdk/compare/31f49b2..fdb2545). [Full SARIF SDK release history](https://github.com/microsoft/sarif-sdk/blob/fdb2545/src/ReleaseHistory.md).
- DEP: Update `spam` executable and dotnet library name to Sarif.PatternMatcher.Cli. 
- DEP: Update `Microsoft.Security.Utilities` to [v1.4.0](https://github.com/microsoft/security-utilities/releases/tag/v1.4.0). [#662](https://github.com/microsoft/sarif-pattern-matcher/pull/662)
- DEP: Upgrade `Microsoft.Security.Utilities` from 1.1.0 to 1.3.0. [#642](https://github.com/microsoft/sarif-pattern-matcher/pull/642)
- DEP: Sarif.PatternMatcher projects will start using a fixed version of `RE2.Managed` and `Strings.Interop`. [#638](https://github.com/microsoft/sarif-pattern-matcher/pull/638)
- BRK: Properly introduce fingerprint versioned hierarchical strings (according to the [SARIF spec](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317441)) by updating `/current` component to `/v0`. 
- BRK: Remove non-functional `multiline` argument from command-line. This argument should simply be removed from all command-lines.
- BRK: Remove `file-size-in-kb` argument. Its use should be replaced by `max-file-size-in-kb`, a more descriptive name we pick up from the SARIF driver framework.
- BRK: Fix bug resulting in static validators returning `FailureLevel.Note` despite configured `FailureLevel`. [#645](https://github.com/microsoft/sarif-pattern-matcher/pull/645)
- BRK: Rename `SEC101/050.IdentifiableNpmLegacyAuthorToken` to `SEC101/050.NpmIdentifiableAuthorToken` [#683](https://github.com/microsoft/sarif-pattern-matcher/pull/683)
- BRK: Rename `SEC101/017.NpmAuthorToken` to `SEC101/017.NpmAuthorToken` [#683](https://github.com/microsoft/sarif-pattern-matcher/pull/683)
- BRK: Rename `SEC101/006.GitHubPat` to `SEC101/006.GitHubLegacyPat` [#678](https://github.com/microsoft/sarif-pattern-matcher/pull/678)
- BRK: Disable `SEC101/029.AlibabaCloudCredentials` which throws ScanErrors with message: 
	>ValidationError:Could not load file or assembly 'AlibabaCloud.OpenApiClient, Version=0.1.4.0, Culture=neutral, PublicKeyToken=null' or one of its dependencies. A strongly-named assembly is required. (Exception from HRESULT: 0x80131044)
  These exceptions are caused by incompatibilities between Alibaba code and .Net core 3.1 and 6.0. Will restore rule when dependencies are updated. [#700](https://github.com/microsoft/sarif-pattern-matcher/pull/700)
- RRR: Rename `SEC101/050.IdentifiableNpmLegacyAuthorToken` to `SEC101/050.NpmIdentifiableAuthorToken` [#683](https://github.com/microsoft/sarif-pattern-matcher/pull/683)
- RRR: Rename `SEC101/017.NpmAuthorToken` to `SEC101/017.NpmAuthorToken` [#683](https://github.com/microsoft/sarif-pattern-matcher/pull/683)
- RRR: Rename `SEC101/006.GitHubPat` to `SEC101/006.GitHubLegacyPat` [#678](https://github.com/microsoft/sarif-pattern-matcher/pull/678)
- FNS: Edit `SEC101/028.PlaintextPassword` regular expression to include scenarios where a variable name is used instead of string (added `*` after `["']`).
- BUG: Update search definitions probing logic to look for file alongside the client tool.
- BUG: Resolve `OutofMemoryException` and `NullReferenceException' failures resulting from a failure to honor file size scan limits set by `--file-size-in-kb` argument and updated Sarif.Sdk submodule to commit [ce8c5cb12d29aa407d0bf98f5fa2c764ec7fb65b](https://github.com/microsoft/sarif-sdk/commit/ce8c5cb12d29aa407d0bf98f5fa2c764ec7fb65b). [#621](https://github.com/microsoft/sarif-pattern-matcher/pull/621)
- BUG: Resolve SAL Modernization Plugin capture group showing incorrect region properties in SARIF. [#626](https://github.com/microsoft/sarif-pattern-matcher/pull/626)
- BUG: Fix false negative when `SearchSkimmer` is invoked directly and `MaxFileSizeInKilobytes` is not set. This will now default to approximately 10MB. [#637](https://github.com/microsoft/sarif-pattern-matcher/pull/637)
- BUG: Loosen `Newtonsoft.Json` minimum version requirement to 12.0.3 for `Sarif.PatternMatcher` project. [#644](https://github.com/microsoft/sarif-pattern-matcher/pull/644)
- NEW: Allow rule disabling from definitions file by adding `"RuleEnabledState: "Disabled""` to rule MatchExpression.
- NEW: Support persisting CodeQL rolling hash partial fingerprints to SARIF output.

## *v1.10.0*
- BRK: Change fingerprint naming conventions and add new unique secret fingerprint (and opaque unique fingerprint hash).
- BUG: RE2.Native will now compile in all environments with the latest Windows SDK 10.0.* installed. [#607](https://github.com/microsoft/sarif-pattern-matcher/pull/607). Our current release pipelines build NuGet packages with Windows SDK version 10.0.22000.
- NEW: Enable response file parsing provided by driver framework. Arguments (e.g., '@Commands.rsp') prefixed with a '@' character will be evaluated as a file path to a text file that contains commands to be injected on the command-line. 

## *v1.9.0*
- DEP: Upgrade `MongoDB.Driver` from 2.13.1 to 2.15.0 and Microsoft.AspNetCore.Http from 2.1.0 to 2.2.0. [#608](https://github.com/microsoft/sarif-pattern-matcher/pull/608)
- DEP: Upgrade `Sarif.Sdk` from 2.4.13 to [2.4.15](https://github.com/microsoft/sarif-sdk/blob/v2.4.15/src/ReleaseHistory.md) by updating submodule to commit [9f0eed7549736b28d59a2e93f443ba47e3bd978e](https://github.com/microsoft/sarif-sdk/commit/9f0eed7549736b28d59a2e93f443ba47e3bd978e). [#612](https://github.com/microsoft/sarif-pattern-matcher/pull/612)
- NR : Adding Url rule in the plugin `ReviewPotentiallySensitiveData`. [#611](https://github.com/microsoft/sarif-pattern-matcher/pull/611)

## *v1.8.0*
- BUG: Resolve `InvalidOperationException` and `IndexOutOfRange` exceptions in `StaticValidatorBase.IsValidStatic` due to unsafe use of HashSet<string> class. [#595](https://github.com/microsoft/sarif-pattern-matcher/pull/585)
- NR : Add `SEC101/048.SlackWorkflow` rule with dynamic validation. [#585](https://github.com/microsoft/sarif-pattern-matcher/pull/585)
- NR : Add `SEC101/049.TelegramBotToken` rule with dynamic validation. [#587](https://github.com/microsoft/sarif-pattern-matcher/pull/587)
- NR : Add `SEC101/017.NpmLegacyAuthorToken` rule with dynamic validation. [#588](https://github.com/microsoft/sarif-pattern-matcher/pull/588)
- NEW: Provide `automationId`, `automationGuid`, and `postUri` in the `analyze` command. [#586](https://github.com/microsoft/sarif-pattern-matcher/pull/586)
    
## *v1.5.0-g9f639c22c7*
- FPC: Improving RabbitMQ regex (removing new lines and spaces) from secret. [#548](https://github.com/microsoft/sarif-pattern-matcher/pull/548)
- FND: Improving `SEC101/018.TwilioCredentials` dynamic validation for test credentials. [#549](https://github.com/microsoft/sarif-pattern-matcher/pull/549)
- FPC: Normalizing regular expressions (`\s\n` got replaced by `\s`). Rules `SEC101/036.MySqlCredential`, `SEC101/037.SqlCredentials`, `SEC101/038.PostgreSqlCredentials` won't accept spaces in `id` and `secret`. [#550](https://github.com/microsoft/sarif-pattern-matcher/pull/550)
- SDK: Single match expression can run multiple regex types. [#553](https://github.com/microsoft/sarif-pattern-matcher/pull/553)
- FPC: Eliminate whitespace and commas from MongoDB match candidates (and resulting fingerprints). [#554](https://github.com/microsoft/sarif-pattern-matcher/pull/554)
- FPC: Improving regular expressions for rules `SEC101/036.MySqlCredentials`, `SEC101/038.PostgreSqlCredentials`, and `SEC101/041.RabbitMqCredentials` removing invalid characters (`,`, `=`, `|`, `&`, `[`, `]`, `>`) from `Id` and `Resource`. [#555](https://github.com/microsoft/sarif-pattern-matcher/pull/555)
- RRR: Improving `SEC101/025.SendGridApiKeyValidator` dynamic validator, replacing tcp for http calls, retrieving the scope of the key if available. [#562](https://github.com/microsoft/sarif-pattern-matcher/pull/562)

## *v1.5.0-alpha-0117-g136d47026e*
- NEW: Required properties will throw `KeyNotFoundException` if they do not exist. [#539](https://github.com/microsoft/sarif-pattern-matcher/pull/539)
- BUG: Tool should emit fixes with comprehensive region properties. [#540](https://github.com/microsoft/sarif-pattern-matcher/pull/540)
- NEW: Added `Fixes` property in SEC104 rules that provide only one option. [#541](https://github.com/microsoft/sarif-pattern-matcher/pull/541)
- UER: Reducing unhandled exceptions for the certificate rules. [#544](https://github.com/microsoft/sarif-pattern-matcher/pull/544)
- UER: Added a check for PostgreSql instances that are not reachable from external networks, reducing total unhandled exceptions. [#545](https://github.com/microsoft/sarif-pattern-matcher/pull/545)
  
## *v1.5.0-alpha-0109-gf687e5e98a*
- NR: Adding CratesApiKey rule with dynamic validation. [#531](https://github.com/microsoft/sarif-pattern-matcher/pull/531)
- Replacing `\b` to the correct border regular expression reducing false positives. [#533](https://github.com/microsoft/sarif-pattern-matcher/pull/533)
- Tool Improvement: Refactoring `ValidatorBase` in `StaticValidatorBase` and `DynamicValidatorBase`. [#534](https://github.com/microsoft/sarif-pattern-matcher/pull/534)

## *v1.5.0-alpha-0100-g6ee5829558*
- [6ee5829](https://github.com/microsoft/sarif-pattern-matcher/commit/6ee5829) Adding tests for NPM rule (#525)
- [640f7f6](https://github.com/microsoft/sarif-pattern-matcher/commit/640f7f6) Making HttpClient static again when not using in tests (#526)
- [4ca1e08](https://github.com/microsoft/sarif-pattern-matcher/commit/4ca1e08) Create Mock Http tests for Slack Tokens (#524)
- [e33d3ca](https://github.com/microsoft/sarif-pattern-matcher/commit/e33d3ca) Add mock http calls to DiscordValidatorTests (#523)
- [7b09519](https://github.com/microsoft/sarif-pattern-matcher/commit/7b09519) Enabling multiple threads for testing (#522)
- [f4bf0fa](https://github.com/microsoft/sarif-pattern-matcher/commit/f4bf0fa) Cleaning httpclient after test (#521)
- [9466ea6](https://github.com/microsoft/sarif-pattern-matcher/commit/9466ea6) Fixing collection name
- [358fef0](https://github.com/microsoft/sarif-pattern-matcher/commit/358fef0) Updating MockHelper and CommonAssemblyInfo (#520)
- [d7da9f5](https://github.com/microsoft/sarif-pattern-matcher/commit/d7da9f5) Crc helpers (#518)
- [285b41a](https://github.com/microsoft/sarif-pattern-matcher/commit/285b41a) Enabling GitHubAppCredentials dynamic validator (#516)
- [575a568](https://github.com/microsoft/sarif-pattern-matcher/commit/575a568) Rename CreateHttpClient to CreateOrUseCachedHttpClient (#517)
- [06ff25f](https://github.com/microsoft/sarif-pattern-matcher/commit/06ff25f) Add Square Credentials Dynamic Validator (#515)
- [6e9a22f](https://github.com/microsoft/sarif-pattern-matcher/commit/6e9a22f) Nuget refinement (#514)
- [23dc3fe](https://github.com/microsoft/sarif-pattern-matcher/commit/23dc3fe) Improving exception handling for Crypto rule (#513)

## *v1.5.0-alpha-0086-gfe5f68dd32*
- [fe5f68d](https://github.com/microsoft/sarif-pattern-matcher/commit/fe5f68d) Updating release notes and submodules (#511)
- [4cab00f](https://github.com/microsoft/sarif-pattern-matcher/commit/4cab00f) Test StripeKey should be warning (#510)
- [6874534](https://github.com/microsoft/sarif-pattern-matcher/commit/6874534) Fixing wrong resultlevelkind in cache (#509)
- [b0a590e](https://github.com/microsoft/sarif-pattern-matcher/commit/b0a590e) Adding AzureHosts to SqlCredentials (#508)
- [d2e8627](https://github.com/microsoft/sarif-pattern-matcher/commit/d2e8627) Removing false-positives from NugetCredential validator (#506)
- [1ee9698](https://github.com/microsoft/sarif-pattern-matcher/commit/1ee9698) Fix PostgreSQL to properly handle Azure hosts. (#507)
- [c69ae7a](https://github.com/microsoft/sarif-pattern-matcher/commit/c69ae7a) Fix MySQL to properly handle Azure hosts. (#505)
- [f161728](https://github.com/microsoft/sarif-pattern-matcher/commit/f161728) ValidationResult should always point to secret region (#504)
- [3d10479](https://github.com/microsoft/sarif-pattern-matcher/commit/3d10479) Improving docs (#503)
- [35f2f12](https://github.com/microsoft/sarif-pattern-matcher/commit/35f2f12) Added Validator for Discord API credentials (#501)
- [bfaf73f](https://github.com/microsoft/sarif-pattern-matcher/commit/bfaf73f) Updating crearting plugin docs (#502)
- [00d0792](https://github.com/microsoft/sarif-pattern-matcher/commit/00d0792) Move all regexes to same layout (#498)
- [70093ed](https://github.com/microsoft/sarif-pattern-matcher/commit/70093ed) Adding security policy (#500)
- [8d0596f](https://github.com/microsoft/sarif-pattern-matcher/commit/8d0596f) SqlCredential - Separating port from host (#499)
- [43d9847](https://github.com/microsoft/sarif-pattern-matcher/commit/43d9847) HelpUri should be configurable (#497)
- [7982b7f](https://github.com/microsoft/sarif-pattern-matcher/commit/7982b7f) Improving MySql and PostgreSql validator (#496)
- [3481bcf](https://github.com/microsoft/sarif-pattern-matcher/commit/3481bcf) Improving postgres regex
- [c6c3624](https://github.com/microsoft/sarif-pattern-matcher/commit/c6c3624) Fixing ArgumentException during ValidatingVisitor analysis (#495)

## *v1.5.0-alpha-0068-g5d32a6446f*

- [5d32a64](https://github.com/microsoft/sarif-pattern-matcher/commit/5d32a64) ValidatingVisitor should prefer v2 if exists (#494)

## *v1.5.0-alpha-0067-gaa1e470c62*

- [aa1e470](https://github.com/microsoft/sarif-pattern-matcher/commit/aa1e470) Removing Path from fingerprint hash if option enabled (#493)

## *v1.5.0-alpha-0066-ge3dc23555d*

- [e3dc235](https://github.com/microsoft/sarif-pattern-matcher/commit/e3dc235) Enable json fingerprint (#492)

## *v1.5.0-alpha-0065-g2c23518427*

- [2c23518](https://github.com/microsoft/sarif-pattern-matcher/commit/2c23518) Propagate changes in fingerprint after dynamic validation (#491)
- [8b9cfed](https://github.com/microsoft/sarif-pattern-matcher/commit/8b9cfed) Adding flag to persist path in asset fingerprint (#490)

## *v1.5.0-alpha-0063-g9868382c12*

- [9868382](https://github.com/microsoft/sarif-pattern-matcher/commit/9868382) Fixing AssetFingerprint when used in ValidatingVisitor (#489)
- [6f00a60](https://github.com/microsoft/sarif-pattern-matcher/commit/6f00a60) Provide alternate JSON fingerprint (#488)
- [b9b42ec](https://github.com/microsoft/sarif-pattern-matcher/commit/b9b42ec) Adding deprecated name to sarif (#485)
- [53013a8](https://github.com/microsoft/sarif-pattern-matcher/commit/53013a8) Preventing new dictionary allocation (#486)
- [36580c4](https://github.com/microsoft/sarif-pattern-matcher/commit/36580c4) Fixing shared properties (#484)

## *v1.5.0-alpha-0058-g154cef6547*

- [154cef6](https://github.com/microsoft/sarif-pattern-matcher/commit/154cef6) Fixing null reference, adding secret change (#483)
- [132a8ce](https://github.com/microsoft/sarif-pattern-matcher/commit/132a8ce) Fixing ValidatingVisitor exception (due to  renaming) (#482)
- [429e09f](https://github.com/microsoft/sarif-pattern-matcher/commit/429e09f) Changing asset fingerprint of GitHubPat rule (#481)
- [49e0989](https://github.com/microsoft/sarif-pattern-matcher/commit/49e0989) Improving ValidatingVisitor and regex (#480)
- [094ca63](https://github.com/microsoft/sarif-pattern-matcher/commit/094ca63) Catch FormatException when converting (#479)

## *v1.5.0-alpha-0053-gd852f2a085*

- [d852f2a](https://github.com/microsoft/sarif-pattern-matcher/commit/d852f2a) Fixing analyze database conversion (#478)
- [02a61d8](https://github.com/microsoft/sarif-pattern-matcher/commit/02a61d8) Renaming connectionString rules (#477)

## *v1.5.0-alpha-0051-ga2d0d590dc*

- [a2d0d59](https://github.com/microsoft/sarif-pattern-matcher/commit/a2d0d59) Improving NugetCredentials and Postgres regex (#476)

## *v1.5.0-alpha-0050-gb2e9608cc5*

- [b2e9608](https://github.com/microsoft/sarif-pattern-matcher/commit/b2e9608) Preparing release (#475)
- [b664d51](https://github.com/microsoft/sarif-pattern-matcher/commit/b664d51) Replacing Guid.NewGuid for ScanId (#474)
- [ad3a04e](https://github.com/microsoft/sarif-pattern-matcher/commit/ad3a04e) Improving cert validator (#473)
- [f63927a](https://github.com/microsoft/sarif-pattern-matcher/commit/f63927a) Postgres single line refactor (#472)
- [43db81e](https://github.com/microsoft/sarif-pattern-matcher/commit/43db81e) Improve SQL region selection. (#471)
- [0e3422e](https://github.com/microsoft/sarif-pattern-matcher/commit/0e3422e) MySQL single line refactor (#470)
- [21d86c8](https://github.com/microsoft/sarif-pattern-matcher/commit/21d86c8) Update azure-pipelines.yml for Azure Pipelines
- [e457fe2](https://github.com/microsoft/sarif-pattern-matcher/commit/e457fe2) Sql singleline (#469)
- [cf8144a](https://github.com/microsoft/sarif-pattern-matcher/commit/cf8144a) Author single-line, multicomponent analysis. (#466)
- [d4e28bf](https://github.com/microsoft/sarif-pattern-matcher/commit/d4e28bf) Enable FlexMatch.ToString() (#467)
- [37c80e9](https://github.com/microsoft/sarif-pattern-matcher/commit/37c80e9) Improving intrafile regex (#464)
- [3596c40](https://github.com/microsoft/sarif-pattern-matcher/commit/3596c40) Removing unnamed groups (#465)
- [6fe0618](https://github.com/microsoft/sarif-pattern-matcher/commit/6fe0618) Fixing NullReferenceException in FlexMatchComparer (#463)
- [8b53832](https://github.com/microsoft/sarif-pattern-matcher/commit/8b53832) Singleline regexes (#462)
- [bd853a7](https://github.com/microsoft/sarif-pattern-matcher/commit/bd853a7) Fixing HttpClient cache (#461)
- [cb3b499](https://github.com/microsoft/sarif-pattern-matcher/commit/cb3b499) Remove 'matchedPattern' argument from static validator phase. Instead… (#460)
- [a9846e1](https://github.com/microsoft/sarif-pattern-matcher/commit/a9846e1) Update SDK. (#458)
- [1e4e5b9](https://github.com/microsoft/sarif-pattern-matcher/commit/1e4e5b9) Adding postman validator (#456)
- [aa8f6e4](https://github.com/microsoft/sarif-pattern-matcher/commit/aa8f6e4) Applying intrafile refactor (#454)
- [c3d10e4](https://github.com/microsoft/sarif-pattern-matcher/commit/c3d10e4) Sarif update (#457)
- [3334a80](https://github.com/microsoft/sarif-pattern-matcher/commit/3334a80) Fixing maxmemory conversion for default value (#455)
- [ef718d6](https://github.com/microsoft/sarif-pattern-matcher/commit/ef718d6) Unhandled response code helper (#452)
- [0033e7d](https://github.com/microsoft/sarif-pattern-matcher/commit/0033e7d) Do not dispose HttpClient (#451)
- [95b153a](https://github.com/microsoft/sarif-pattern-matcher/commit/95b153a) Changing code coverage (#453)
- [cbde3c8](https://github.com/microsoft/sarif-pattern-matcher/commit/cbde3c8) Improve match efficiency. Provide two specific examples. (#447)
- [438ef03](https://github.com/microsoft/sarif-pattern-matcher/commit/438ef03) Adding retry and max-memory options (#445)
- [152e71b](https://github.com/microsoft/sarif-pattern-matcher/commit/152e71b) New intrafile analysis (#446)
- [9931610](https://github.com/microsoft/sarif-pattern-matcher/commit/9931610) Fixing coverage (#444)
- [e31a53c](https://github.com/microsoft/sarif-pattern-matcher/commit/e31a53c) Add test cases for ValidationResult (#443)

## *v1.5.0-alpha-0021-gd7197e02cd*

- [d7197e0](https://github.com/microsoft/sarif-pattern-matcher/commit/d7197e0) Replace file name in output with a truncated secret. (#442)

## *v1.5.0-alpha-0020-g427c4d51a5*

- [427c4d5](https://github.com/microsoft/sarif-pattern-matcher/commit/427c4d5) Update contributing (#441)
- [047e8be](https://github.com/microsoft/sarif-pattern-matcher/commit/047e8be) Add override index to ValidationResult (#431)
- [de0b97e](https://github.com/microsoft/sarif-pattern-matcher/commit/de0b97e) Git validator (#440)
- [5f93b47](https://github.com/microsoft/sarif-pattern-matcher/commit/5f93b47) Implement max memory option for RE2 regex (#438)
- [d9b3516](https://github.com/microsoft/sarif-pattern-matcher/commit/d9b3516) Switch from non-overlapping to overlapping matches (#439)

## *v1.5.0-alpha-0015-g11d2baa765*

- [11d2baa](https://github.com/microsoft/sarif-pattern-matcher/commit/11d2baa) updating sarif-sdk submodules (v2.4.8) (#437)
- [117a990](https://github.com/microsoft/sarif-pattern-matcher/commit/117a990) Analyze database command (#424)
- [5021fe8](https://github.com/microsoft/sarif-pattern-matcher/commit/5021fe8) Fixing empty text analysis (#436)
- [e6ff77c](https://github.com/microsoft/sarif-pattern-matcher/commit/e6ff77c) Refactor stringUtf8 (#435)
- [8918452](https://github.com/microsoft/sarif-pattern-matcher/commit/8918452) Replacing .NET regex for RE2 regex (#414)
- [86e60fa](https://github.com/microsoft/sarif-pattern-matcher/commit/86e60fa) Handle end match case (#434)
- [cdfb104](https://github.com/microsoft/sarif-pattern-matcher/commit/cdfb104) Fix issue in shared string interpretation. (#432)
- [fa2340f](https://github.com/microsoft/sarif-pattern-matcher/commit/fa2340f)  Convert UTF-8 match indices to UTF-16 (#433)
- [7732151](https://github.com/microsoft/sarif-pattern-matcher/commit/7732151) Fixing conversion (submodules) (#430)
- [02ace2a](https://github.com/microsoft/sarif-pattern-matcher/commit/02ace2a) Adding ownership message (submodules) (#429)
- [e749c7e](https://github.com/microsoft/sarif-pattern-matcher/commit/e749c7e) Updating FileRegionsCache (submodule) (#428)
- [780eeef](https://github.com/microsoft/sarif-pattern-matcher/commit/780eeef) Adding ownership from submodules (#427)
- [b1432e6](https://github.com/microsoft/sarif-pattern-matcher/commit/b1432e6) Improving kusto messages (submodule) (#426)
- [a72b8f0](https://github.com/microsoft/sarif-pattern-matcher/commit/a72b8f0) Updating kusto messages (sarif-sdk submodule) (#425)
- [fd92e6e](https://github.com/microsoft/sarif-pattern-matcher/commit/fd92e6e) Changing back to alpha (#423)

## *v1.4.0-g6e8cafe228*

- [6e8cafe](https://github.com/microsoft/sarif-pattern-matcher/commit/6e8cafe) Releasing stable version (#422)
- [a75ad6b](https://github.com/microsoft/sarif-pattern-matcher/commit/a75ad6b) NpmCredentialsValidator (#420)
- [886d4f5](https://github.com/microsoft/sarif-pattern-matcher/commit/886d4f5) Add test for different overlapping implementations (#419)
- [a34bb4d](https://github.com/microsoft/sarif-pattern-matcher/commit/a34bb4d) Updating sarif-sdk submodule (#421)
- [7700140](https://github.com/microsoft/sarif-pattern-matcher/commit/7700140) Improving RE2 performance (#416)
- [4d2de5d](https://github.com/microsoft/sarif-pattern-matcher/commit/4d2de5d) Fix handling of optional groups in RE2 wrapper (#417)
- [feedca5](https://github.com/microsoft/sarif-pattern-matcher/commit/feedca5) Fixing dynamic validation message (#415)
- [79d3e49](https://github.com/microsoft/sarif-pattern-matcher/commit/79d3e49) Updating sarif-sdk submodules (#413)
- [74dfe13](https://github.com/microsoft/sarif-pattern-matcher/commit/74dfe13) Implement multi-matching for named groups (#411)
- [abd2a9e](https://github.com/microsoft/sarif-pattern-matcher/commit/abd2a9e) Improving SecureApi rules (#412)
- [9dd53bd](https://github.com/microsoft/sarif-pattern-matcher/commit/9dd53bd) Fixing package vulnerability (#410)
- [23e3a33](https://github.com/microsoft/sarif-pattern-matcher/commit/23e3a33) Updating sarif-sdk submodules (#409)
- [cb6d799](https://github.com/microsoft/sarif-pattern-matcher/commit/cb6d799) Enable CodeCoverage when using EnableCoverage (#408)
- [dab173f](https://github.com/microsoft/sarif-pattern-matcher/commit/dab173f) Improving nuget rule (#407)
- [a2c2894](https://github.com/microsoft/sarif-pattern-matcher/commit/a2c2894) Improving MySql validator (#406)
- [8663b29](https://github.com/microsoft/sarif-pattern-matcher/commit/8663b29) Improving kusto query (#405)
- [0277921](https://github.com/microsoft/sarif-pattern-matcher/commit/0277921) Improving SAL messages (#404)

## *v1.4.0-alpha-0293-g5d749ed3d0*

- [5d749ed](https://github.com/microsoft/sarif-pattern-matcher/commit/5d749ed) Fixing command line (#403)

## *v1.4.0-alpha-0292-g333441a1c9*

- [333441a](https://github.com/microsoft/sarif-pattern-matcher/commit/333441a) Updating submodules (#402)

## *v1.4.0-alpha-0291-gb869932a54*

- [b869932](https://github.com/microsoft/sarif-pattern-matcher/commit/b869932) Improving SubId MessageStrings/RuleId handling (#401)
- [e6bc997](https://github.com/microsoft/sarif-pattern-matcher/commit/e6bc997) Enabling Pass in SearchDefinition (#398)
- [3922574](https://github.com/microsoft/sarif-pattern-matcher/commit/3922574) Add new validator for Nuget Credentials (#372)
- [ca6801b](https://github.com/microsoft/sarif-pattern-matcher/commit/ca6801b) Use 32-bit signed integers throughout implementation for named capturing groups (#397)
- [1eacbe3](https://github.com/microsoft/sarif-pattern-matcher/commit/1eacbe3) Update contributing (#396)
- [8862e0d](https://github.com/microsoft/sarif-pattern-matcher/commit/8862e0d) ResultLevelKind should be ref (#395)
- [d83a571](https://github.com/microsoft/sarif-pattern-matcher/commit/d83a571) sql/mysql validator improvement (#394)
- [d89253e](https://github.com/microsoft/sarif-pattern-matcher/commit/d89253e) Improving SAL message strings (#388)
- [86152e5](https://github.com/microsoft/sarif-pattern-matcher/commit/86152e5) Improving SQL regex (#393)
- [47d9052](https://github.com/microsoft/sarif-pattern-matcher/commit/47d9052) Refactor dynamic methods (#389)
- [e4a5c76](https://github.com/microsoft/sarif-pattern-matcher/commit/e4a5c76) ResultKindLevel refactor (#387)
- [7231b76](https://github.com/microsoft/sarif-pattern-matcher/commit/7231b76) named capturing groups using RE2 (#381)
- [e343b0b](https://github.com/microsoft/sarif-pattern-matcher/commit/e343b0b) Improving import-and-analyze command (#384)
- [45fceeb](https://github.com/microsoft/sarif-pattern-matcher/commit/45fceeb) Use file has as secret in file extension checks with no validator. (#385)

## *v1.4.0-alpha-0277-g74bb923045*

- [74bb923](https://github.com/microsoft/sarif-pattern-matcher/commit/74bb923) Improving mysql validator (#383)
- [a8c872f](https://github.com/microsoft/sarif-pattern-matcher/commit/a8c872f) Adding inactive account for slack (#382)

## *v1.4.0-alpha-0275-g6b3254faeb*

- [6b3254f](https://github.com/microsoft/sarif-pattern-matcher/commit/6b3254f) Refactoring fingerprint (#380)
- [273a4d5](https://github.com/microsoft/sarif-pattern-matcher/commit/273a4d5) Update HttpAuthorizationRequestHeaderValidator (#379)
- [5d04548](https://github.com/microsoft/sarif-pattern-matcher/commit/5d04548) Update mongo DB regex, add test case (#378)
- [ed6415e](https://github.com/microsoft/sarif-pattern-matcher/commit/ed6415e) Improving httpAuthorization (#377)
- [cb70ab2](https://github.com/microsoft/sarif-pattern-matcher/commit/cb70ab2) Fingerprint should not require Provider (#376)
- [860a33f](https://github.com/microsoft/sarif-pattern-matcher/commit/860a33f) Add debugging unit test (#369)
- [32da8f0](https://github.com/microsoft/sarif-pattern-matcher/commit/32da8f0) Add deprecated name to exported rules markdown. (#375)

## *v1.4.0-alpha-0268-gb482699566*

- [b482699](https://github.com/microsoft/sarif-pattern-matcher/commit/b482699) Fixing dll movements (#374)
- [6403c39](https://github.com/microsoft/sarif-pattern-matcher/commit/6403c39) Fixing CVE-2021-24112 (#373)
- [4ea05ca](https://github.com/microsoft/sarif-pattern-matcher/commit/4ea05ca) Import and analyze (#368)

## *v1.4.0-alpha-0265-g1ff44b1a6d*

- [1ff44b1](https://github.com/microsoft/sarif-pattern-matcher/commit/1ff44b1) Add regex for new GitHub PAT (#366)
- [15b2be7](https://github.com/microsoft/sarif-pattern-matcher/commit/15b2be7) Improving nupkg file movements (#370)
- [425ee1b](https://github.com/microsoft/sarif-pattern-matcher/commit/425ee1b) Updating submodules (#367)

## *v1.4.0-alpha-0262-gdbe94bb457*

- [dbe94bb](https://github.com/microsoft/sarif-pattern-matcher/commit/dbe94bb) Fixing indentation and twilio validator (#364)
- [ae0a3a2](https://github.com/microsoft/sarif-pattern-matcher/commit/ae0a3a2) Cloudant (#362)
- [52a9a5e](https://github.com/microsoft/sarif-pattern-matcher/commit/52a9a5e) Examine innerexception for timeouts (#361)
- [611a3bc](https://github.com/microsoft/sarif-pattern-matcher/commit/611a3bc) Enforce that no notifications are generated during file diff tests. (#360)
- [e1b3ff3](https://github.com/microsoft/sarif-pattern-matcher/commit/e1b3ff3) Update SDK API. (#359)
- [13ac5bb](https://github.com/microsoft/sarif-pattern-matcher/commit/13ac5bb) Add SalModernization plugin (#347)
- [1714a34](https://github.com/microsoft/sarif-pattern-matcher/commit/1714a34) Minor improvement (#357)
- [db6cecf](https://github.com/microsoft/sarif-pattern-matcher/commit/db6cecf) Part in asset fingerprint only (#358)
- [71bb99f](https://github.com/microsoft/sarif-pattern-matcher/commit/71bb99f) Resource provider and type (#356)
- [6db9feb](https://github.com/microsoft/sarif-pattern-matcher/commit/6db9feb) Renaming rules (#355)
- [75ca3f5](https://github.com/microsoft/sarif-pattern-matcher/commit/75ca3f5) Add case for PostgreSql (#354)
- [6da552f](https://github.com/microsoft/sarif-pattern-matcher/commit/6da552f) Rule name conventions (#353)
- [1d31777](https://github.com/microsoft/sarif-pattern-matcher/commit/1d31777) Tweak HttpAuthorizationRequestHeader (#352)
- [b2a5950](https://github.com/microsoft/sarif-pattern-matcher/commit/b2a5950) Account to id. (#351)
- [4db73df](https://github.com/microsoft/sarif-pattern-matcher/commit/4db73df) Exporting rules metadata (#350)
- [faf82bc](https://github.com/microsoft/sarif-pattern-matcher/commit/faf82bc) Fingerprint simplification (#349)
- [dc4850a](https://github.com/microsoft/sarif-pattern-matcher/commit/dc4850a) MovingFiles after building (#348)
- [aeecbeb](https://github.com/microsoft/sarif-pattern-matcher/commit/aeecbeb) Fake credentials.
- [456d341](https://github.com/microsoft/sarif-pattern-matcher/commit/456d341) Cleaning warnings (#346)
- [1a0ce93](https://github.com/microsoft/sarif-pattern-matcher/commit/1a0ce93) Retrieve unknown host from exception (#345)
- [e4588b5](https://github.com/microsoft/sarif-pattern-matcher/commit/e4588b5) Refactor ValidatorBase (#344)
- [9350fa8](https://github.com/microsoft/sarif-pattern-matcher/commit/9350fa8) Commenting Alibaba DynamicValidator (#343)
- [136c0f5](https://github.com/microsoft/sarif-pattern-matcher/commit/136c0f5) Improving validators (#341)
- [2e21134](https://github.com/microsoft/sarif-pattern-matcher/commit/2e21134) Various fixes for windows. Truncate shannon entropy to two decimal places. (#342)
- [68bce5c](https://github.com/microsoft/sarif-pattern-matcher/commit/68bce5c) Akamai validator (#339)
- [d469a5c](https://github.com/microsoft/sarif-pattern-matcher/commit/d469a5c) Update SARIF SDK (#340)

## *v1.4.0-alpha-0236-ge5606a2332*

- [e5606a2](https://github.com/microsoft/sarif-pattern-matcher/commit/e5606a2) Removing Hockey and GCM validator (#337)
- [def439d](https://github.com/microsoft/sarif-pattern-matcher/commit/def439d) Improving RabbitMQ regex/tests (#336)
- [485a409](https://github.com/microsoft/sarif-pattern-matcher/commit/485a409) Adding more tests (#335)
- [935bc79](https://github.com/microsoft/sarif-pattern-matcher/commit/935bc79) Improving slack webhook (#334)
- [4aa28ed](https://github.com/microsoft/sarif-pattern-matcher/commit/4aa28ed) Add rank to all results (which is the normalized shannon entropy of the password/key component of the fingerprint). (#333)
- [891bdd2](https://github.com/microsoft/sarif-pattern-matcher/commit/891bdd2) Testing relative paths while running SEC103 (#329)
- [92714a8](https://github.com/microsoft/sarif-pattern-matcher/commit/92714a8) Enable EnhancedReporting in ValidatingVisitor (#327)
- [9d2de6f](https://github.com/microsoft/sarif-pattern-matcher/commit/9d2de6f) Plaintext password (#328)

## *v1.4.0-alpha-0228-g4eac90f931*

- [4eac90f](https://github.com/microsoft/sarif-pattern-matcher/commit/4eac90f) Fixing PAT regex (#326)
- [e79eb09](https://github.com/microsoft/sarif-pattern-matcher/commit/e79eb09) Adding Sdk to README (#325)
- [f5162bf](https://github.com/microsoft/sarif-pattern-matcher/commit/f5162bf) Improving regex and file analyzer (#324)
- [12bb143](https://github.com/microsoft/sarif-pattern-matcher/commit/12bb143) Fix some exceptions in scanning (#321)
- [ad653d3](https://github.com/microsoft/sarif-pattern-matcher/commit/ad653d3) Updating sarif-sdk (#323)
- [163d571](https://github.com/microsoft/sarif-pattern-matcher/commit/163d571) Updating sarif-sdk submodule (#322)
- [af12e68](https://github.com/microsoft/sarif-pattern-matcher/commit/af12e68) Updating release history (#320)

## *v1.4.0-alpha-0221-gc18b188ba9*

- [c18b188](https://github.com/microsoft/sarif-pattern-matcher/commit/c18b188) Twilio credential validator (#319)
- [c6a0632](https://github.com/microsoft/sarif-pattern-matcher/commit/c6a0632) RabbitMq Validator (#318)
- [a5b1306](https://github.com/microsoft/sarif-pattern-matcher/commit/a5b1306) MongoDb validator (#316)
- [9ef2fca](https://github.com/microsoft/sarif-pattern-matcher/commit/9ef2fca) Adding dropbox validators (#315)
- [fc2198b](https://github.com/microsoft/sarif-pattern-matcher/commit/fc2198b) Hash validation fingerprint (#312)
- [9b26d3d](https://github.com/microsoft/sarif-pattern-matcher/commit/9b26d3d) Merge PS and Sql Credential Validators (#314)
- [cd2eea6](https://github.com/microsoft/sarif-pattern-matcher/commit/cd2eea6) Adding docs (#313)
- [963f551](https://github.com/microsoft/sarif-pattern-matcher/commit/963f551) Creating Sarif.PatternMatcher.Sdk (#310)
- [2d476bf](https://github.com/microsoft/sarif-pattern-matcher/commit/2d476bf) Testing framework should be configurable (#311)
- [9176c71](https://github.com/microsoft/sarif-pattern-matcher/commit/9176c71) adding well known keys for stripe (#309)
- [bc21b4a](https://github.com/microsoft/sarif-pattern-matcher/commit/bc21b4a) Resolve 'the certificate chain was issued by an authority that is not trusted.' exceptions (#308)
- [e12eef2](https://github.com/microsoft/sarif-pattern-matcher/commit/e12eef2) Updating submodule and ReleaseHistory (#307)
- [e5a88f1](https://github.com/microsoft/sarif-pattern-matcher/commit/e5a88f1) Enhanced reporting (#306)
- [5f8b720](https://github.com/microsoft/sarif-pattern-matcher/commit/5f8b720) FileContent exception handling (#305)
- [7d82475](https://github.com/microsoft/sarif-pattern-matcher/commit/7d82475) Resolve unhandled exception when receiving junk data. (#303)
- [bf5cdb9](https://github.com/microsoft/sarif-pattern-matcher/commit/bf5cdb9) ConcurrentDictionary for ValidatorBase (#302)
- [9dfbb70](https://github.com/microsoft/sarif-pattern-matcher/commit/9dfbb70) Improving performance (sarif-sdk update) (#301)
- [a80aafa](https://github.com/microsoft/sarif-pattern-matcher/commit/a80aafa) Improving message handling (#300)
- [d64ef4f](https://github.com/microsoft/sarif-pattern-matcher/commit/d64ef4f) Update google API key rule. Fix reporting helper. Update windows SDK. (#298)
- [d7e1bff](https://github.com/microsoft/sarif-pattern-matcher/commit/d7e1bff) Fixing comments from previous prs (#299)
- [cebccd6](https://github.com/microsoft/sarif-pattern-matcher/commit/cebccd6) Improving fingerprint parser (#296)

## *v1.4.0-alpha-0198-g840f9cbd87*

- [840f9cb](https://github.com/microsoft/sarif-pattern-matcher/commit/840f9cb) Updating submodules (#292)
- [60b696c](https://github.com/microsoft/sarif-pattern-matcher/commit/60b696c) Fixing fingerprint ordering (#289)
- [9602f06](https://github.com/microsoft/sarif-pattern-matcher/commit/9602f06) Fixing wrong suffix (#291)
- [1c9855e](https://github.com/microsoft/sarif-pattern-matcher/commit/1c9855e) ProjectNotAuthorized should be NoMatch (#290)
- [2dab565](https://github.com/microsoft/sarif-pattern-matcher/commit/2dab565) Adding argument to disable cache (#288)
- [9d714cf](https://github.com/microsoft/sarif-pattern-matcher/commit/9d714cf) New alibaba access key validator (#285)
- [0c54206](https://github.com/microsoft/sarif-pattern-matcher/commit/0c54206) Add new google service account key validator (#280)
- [41d5eb2](https://github.com/microsoft/sarif-pattern-matcher/commit/41d5eb2) Improving regex (#286)
- [b85b783](https://github.com/microsoft/sarif-pattern-matcher/commit/b85b783) Adding dynamic validation for MailChimp and improving regex (#284)
- [4b2fb7d](https://github.com/microsoft/sarif-pattern-matcher/commit/4b2fb7d) Updating AssetPlatform and tests (#283)
- [6995c8e](https://github.com/microsoft/sarif-pattern-matcher/commit/6995c8e) Fixing caching issue while using AzureDevops URL (#282)

## *v1.4.0-alpha-0187-g70c7ddaf47*

- [70c7dda](https://github.com/microsoft/sarif-pattern-matcher/commit/70c7dda) Updating sarif-sdk submodule (#279)
- [9780de1](https://github.com/microsoft/sarif-pattern-matcher/commit/9780de1) Asset fingerprint (#276)
- [ec93a4f](https://github.com/microsoft/sarif-pattern-matcher/commit/ec93a4f) Updating release history (#252)
- [c5e675a](https://github.com/microsoft/sarif-pattern-matcher/commit/c5e675a) Enable NPM Validator (#274)
- [6b96d5a](https://github.com/microsoft/sarif-pattern-matcher/commit/6b96d5a) Move ConvertToSecureString into its own small validator (#271)
- [af6e3fa](https://github.com/microsoft/sarif-pattern-matcher/commit/af6e3fa) Add handling for empty certificate key data. (#273)
- [b90ddf7](https://github.com/microsoft/sarif-pattern-matcher/commit/b90ddf7) Check if all rules have validators (#250)
- [579d2b0](https://github.com/microsoft/sarif-pattern-matcher/commit/579d2b0) Filename should be unique (#270)

## *v1.4.0-alpha-0179-gad1976d55c*

- [08014ba](https://github.com/microsoft/sarif-pattern-matcher/commit/08014ba) sarif sdk kusto update (#254)
- [005bb06](https://github.com/microsoft/sarif-pattern-matcher/commit/005bb06) Capture a few more scenarios for MySql (#241)
- [221914b](https://github.com/microsoft/sarif-pattern-matcher/commit/221914b) Add CloudantValidator (#238)
- [401d7a6](https://github.com/microsoft/sarif-pattern-matcher/commit/401d7a6) Drop existing  `warning` levels to `note`.  (#261)
- [c66fcf0](https://github.com/microsoft/sarif-pattern-matcher/commit/c66fcf0) Adding default value to FileSize (#262)
- [79dec9c](https://github.com/microsoft/sarif-pattern-matcher/commit/79dec9c) Changing failureLevel when NoMatch (#268)
- [ad1976d](https://github.com/microsoft/sarif-pattern-matcher/commit/ad1976d) Changing failurelevel (#269)

## *v1.4.0-alpha-0172-g222db22101*

- [9842609](https://github.com/microsoft/sarif-pattern-matcher/commit/9842609) Remove sensitive files and git dirs. (#239)
- [01399f1](https://github.com/microsoft/sarif-pattern-matcher/commit/01399f1) Update SARIF-SDK. (#240)
- [cd05c71](https://github.com/microsoft/sarif-pattern-matcher/commit/cd05c71) Update SARIF SDK memory improvements. (#243)
- [8c0e8d3](https://github.com/microsoft/sarif-pattern-matcher/commit/8c0e8d3) Validating self-signed certificate. (#242)
- [7640b10](https://github.com/microsoft/sarif-pattern-matcher/commit/7640b10) Adding limit to size of file when analyzing. (#246)
- [24141a5](https://github.com/microsoft/sarif-pattern-matcher/commit/24141a5) Add new PSCredentialsValidator. (#245)
- [fa8a51a](https://github.com/microsoft/sarif-pattern-matcher/commit/fa8a51a) Correcting Ids. (#248)
- [9594727](https://github.com/microsoft/sarif-pattern-matcher/commit/9594727) Add new SqlCredentialValidator. (#247)
- [a7f98b6](https://github.com/microsoft/sarif-pattern-matcher/commit/a7f98b6) New gpg credential validator. (#249)

## *v1.4.0-alpha-0145-gb5575bfb74*

- [9f48f4b](https://github.com/microsoft/sarif-pattern-matcher/commit/9f48f4b) Exclude spaces from password. (#235)
- [d222802](https://github.com/microsoft/sarif-pattern-matcher/commit/d222802) Updating submodules. (#236)
- [b5575bf](https://github.com/microsoft/sarif-pattern-matcher/commit/b5575bf) Updating submodules. (#237)

## *v1.4.0-alpha-0139-g9be1d98de6*

- [1157582](https://github.com/microsoft/sarif-pattern-matcher/commit/1157582) Renaiming shared strings. (#191)
- [02ec7f2](https://github.com/microsoft/sarif-pattern-matcher/commit/02ec7f2) Add SendGrid dynamic validator. (#192)
- [a42ded6](https://github.com/microsoft/sarif-pattern-matcher/commit/a42ded6) Rename Id from SEC101/101 to SEC101/001 for HttpAuthorization. (#205)
- [4a698c9](https://github.com/microsoft/sarif-pattern-matcher/commit/4a698c9) Improve SqlServer regex. (#211)
- [75ad5b6](https://github.com/microsoft/sarif-pattern-matcher/commit/75ad5b6) Mailgun detection and validator (for new style API keys). (#210)
- [ffd6760](https://github.com/microsoft/sarif-pattern-matcher/commit/ffd6760) Make DomainFilteringHelper public. (#212)
- [434b89c](https://github.com/microsoft/sarif-pattern-matcher/commit/434b89c) Use contains instead of endswith in domain filter. (#215)
- [aa93df3](https://github.com/microsoft/sarif-pattern-matcher/commit/aa93df3) Stripe api key. (#216)
- [d36737c](https://github.com/microsoft/sarif-pattern-matcher/commit/d36737c) Unicode escaping. (#217)
- [8043662](https://github.com/microsoft/sarif-pattern-matcher/commit/8043662) Improvement in GoogleApiKeyValidator. (#218)
- [b2140ed](https://github.com/microsoft/sarif-pattern-matcher/commit/b2140ed) Consolidate LinkedInClientID with LinkedInSecretKey. (#219)
- [d9f6e9d](https://github.com/microsoft/sarif-pattern-matcher/commit/d9f6e9d) Improvement in MySql regex. (#214)
- [0611c68](https://github.com/microsoft/sarif-pattern-matcher/commit/0611c68) Improvement in Postgres regex. (#213)
- [d08554c](https://github.com/microsoft/sarif-pattern-matcher/commit/d08554c) Improvement in HttpAuthorizationRequestHeader validation. (#220)
- [461e3f9](https://github.com/microsoft/sarif-pattern-matcher/commit/461e3f9) Shannon entropy. (#225)
- [e51b689](https://github.com/microsoft/sarif-pattern-matcher/commit/e51b689) Enable net472 support. (#222)
- [f31b380](https://github.com/microsoft/sarif-pattern-matcher/commit/f31b380) Enable Square fingerprint. (#223)
- [e49b511](https://github.com/microsoft/sarif-pattern-matcher/commit/e49b511) Improving message when ValidationState is Authorized for SQL. (#224)
- [3e67905](https://github.com/microsoft/sarif-pattern-matcher/commit/3e67905) Add Slack incoming webhook detection and validator. (#228)
- [256bb43](https://github.com/microsoft/sarif-pattern-matcher/commit/256bb43) Improving unexpected response message. (#230)
- [5665006](https://github.com/microsoft/sarif-pattern-matcher/commit/5665006) Validating certificates if they are already loaded. (#231)
- [1ef2b11](https://github.com/microsoft/sarif-pattern-matcher/commit/1ef2b11) Detector and static validators for some private PEM encoded keys. (#232)
- [306b4ff](https://github.com/microsoft/sarif-pattern-matcher/commit/306b4ff) Updating sarif-sdk submodules. (#233)
- [9be1d98](https://github.com/microsoft/sarif-pattern-matcher/commit/9be1d98) Add puttygen, RSA key pair and ms private key blob patterns to detections. (#234)

## *v1.4.0-alpha-0064-g9308f29e09*

- [9308f29](https://github.com/microsoft/sarif-pattern-matcher/commit/9308f29) Remove FB rule. Improve shared string expansion assert. (#188)
- [6e94da7](https://github.com/microsoft/sarif-pattern-matcher/commit/6e94da7) Reverting last sql change (#187)

## *v1.4.0-alpha-0044-gee1e18ea36*

- [ee1e18e](https://github.com/microsoft/sarif-pattern-matcher/commit/ee1e18e) Adding limits to SQL regex (#167)
- [5875545](https://github.com/microsoft/sarif-pattern-matcher/commit/5875545) updating contributing with more guidelines (#166)
- [09ef181](https://github.com/microsoft/sarif-pattern-matcher/commit/09ef181) Remove ordering in MySql regex (#165)
- [baef865](https://github.com/microsoft/sarif-pattern-matcher/commit/baef865) Ignore pattern if contains tree (#164)
- [25f3c35](https://github.com/microsoft/sarif-pattern-matcher/commit/25f3c35) Fixing connection string for sql (#163)
- [f0c517c](https://github.com/microsoft/sarif-pattern-matcher/commit/f0c517c) Return NoMatch if matchedPattern contains usercontent (#162)

## *v1.4.0-alpha-0038-g669bacd87a*

- [669bacd](https://github.com/microsoft/sarif-pattern-matcher/commit/669bacd) Make PostgreSQL validator order-insensitive (#159)
- [af4c6e0](https://github.com/microsoft/sarif-pattern-matcher/commit/af4c6e0) Order-insensitive for SQL connections (#160)
- [8eb24df](https://github.com/microsoft/sarif-pattern-matcher/commit/8eb24df) Improving GitHub PAT search (#161)

## *v1.4.0-alpha-0035-g4196919fb1*

- [4196919](https://github.com/microsoft/sarif-pattern-matcher/commit/4196919) Renaming ids and fixing Octokit publish (#158)
- [a4b0410](https://github.com/microsoft/sarif-pattern-matcher/commit/a4b0410) PostgreSql Connection String Validator (#157)
- [964318c](https://github.com/microsoft/sarif-pattern-matcher/commit/964318c) Add general Newtonsoft binding redirect. (#156)

## *v1.4.0-alpha-0032-g2224b0944a*

- [2224b09](https://github.com/microsoft/sarif-pattern-matcher/commit/2224b09) MySql improvements (#155)
- [a0fecf6](https://github.com/microsoft/sarif-pattern-matcher/commit/a0fecf6) Ignore expired creds (no dynamic validation. (#153)
- [74bff7b](https://github.com/microsoft/sarif-pattern-matcher/commit/74bff7b) SqlConnectionString validator (#154)
- [a9aa7cf](https://github.com/microsoft/sarif-pattern-matcher/commit/a9aa7cf) trying to improve build time (#152)
- [d3a1e9b](https://github.com/microsoft/sarif-pattern-matcher/commit/d3a1e9b) Azure Database for MySQL validator (#151)
- [dbff24e](https://github.com/microsoft/sarif-pattern-matcher/commit/dbff24e) Gh noise reduction (#150)
- [1dc67ee](https://github.com/microsoft/sarif-pattern-matcher/commit/1dc67ee) Avoid null deref in unknown host exception handling code. (#149)
- [f8be8b2](https://github.com/microsoft/sarif-pattern-matcher/commit/f8be8b2) upgrading coverlet package (#148)

## *v1.4.0-alpha-0024-g3cab78cc0d*

- [3cab78c](https://github.com/microsoft/sarif-pattern-matcher/commit/3cab78c) Clean up exception reporting utility code. (#147)
- [5f68769](https://github.com/microsoft/sarif-pattern-matcher/commit/5f68769) Google API key validator. (#146)
- [7e76c4b](https://github.com/microsoft/sarif-pattern-matcher/commit/7e76c4b) Simplify pat fingerprint name (#145)
- [f9c212e](https://github.com/microsoft/sarif-pattern-matcher/commit/f9c212e) Creating test pattern (#141)
- [40d635d](https://github.com/microsoft/sarif-pattern-matcher/commit/40d635d) Fixing build code coverage (#144)
- [3cf5aba](https://github.com/microsoft/sarif-pattern-matcher/commit/3cf5aba) Reading assemblies before loading (#143)
- [ddbe027](https://github.com/microsoft/sarif-pattern-matcher/commit/ddbe027) Allow for flowing rule properties to rules. (#142)
- [73383a0](https://github.com/microsoft/sarif-pattern-matcher/commit/73383a0) Remove some security checks. Refine validation message processing. (#139)
- [178b74f](https://github.com/microsoft/sarif-pattern-matcher/commit/178b74f) Fixing azure function caching (#138)
- [7ed3a95](https://github.com/microsoft/sarif-pattern-matcher/commit/7ed3a95) Experiments with various OAUTH client id/secret pairs. (#137)
- [82d0aba](https://github.com/microsoft/sarif-pattern-matcher/commit/82d0aba) Gh fixes (#136)
- [ad991ef](https://github.com/microsoft/sarif-pattern-matcher/commit/ad991ef) Updating sarif-sdk submodule (#135)
- [8420c74](https://github.com/microsoft/sarif-pattern-matcher/commit/8420c74) Unknown host utility (#134)
- [e58a09e](https://github.com/microsoft/sarif-pattern-matcher/commit/e58a09e) Update SARIF submodule.
- [691a212](https://github.com/microsoft/sarif-pattern-matcher/commit/691a212) Merge remote-tracking branch 'origin/main' into unknown-host-utility
- [26da762](https://github.com/microsoft/sarif-pattern-matcher/commit/26da762) Update unknown host handler.
- [08f6962](https://github.com/microsoft/sarif-pattern-matcher/commit/08f6962) Improve negative condition reporting in various rules.
- [2189ea1](https://github.com/microsoft/sarif-pattern-matcher/commit/2189ea1) Merge remote-tracking branch 'origin/main' into rule-updates
- [09d7506](https://github.com/microsoft/sarif-pattern-matcher/commit/09d7506) Update test baselines.
- [256299e](https://github.com/microsoft/sarif-pattern-matcher/commit/256299e) Drop all unvalidated results to warning failure level.

## *v1.4.0-alpha-0019-g3cf5aba708*

- [73383a0](https://github.com/microsoft/sarif-pattern-matcher/commit/73383a0) Remove some security checks. Refine validation message processing. (#139)
- [178b74f](https://github.com/microsoft/sarif-pattern-matcher/commit/178b74f) Fixing azure function caching (#138)
- [7ed3a95](https://github.com/microsoft/sarif-pattern-matcher/commit/7ed3a95) Experiments with various OAUTH client id/secret pairs. (#137)
- [82d0aba](https://github.com/microsoft/sarif-pattern-matcher/commit/82d0aba) Gh fixes (#136)
- [ad991ef](https://github.com/microsoft/sarif-pattern-matcher/commit/ad991ef) Updating sarif-sdk submodule (#135)
- [8420c74](https://github.com/microsoft/sarif-pattern-matcher/commit/8420c74) Unknown host utility (#134)
- [e58a09e](https://github.com/microsoft/sarif-pattern-matcher/commit/e58a09e) Update SARIF submodule.
- [691a212](https://github.com/microsoft/sarif-pattern-matcher/commit/691a212) Merge remote-tracking branch 'origin/main' into unknown-host-utility
- [26da762](https://github.com/microsoft/sarif-pattern-matcher/commit/26da762) Update unknown host handler.
- [08f6962](https://github.com/microsoft/sarif-pattern-matcher/commit/08f6962) Improve negative condition reporting in various rules.
- [2189ea1](https://github.com/microsoft/sarif-pattern-matcher/commit/2189ea1) Merge remote-tracking branch 'origin/main' into rule-updates
- [09d7506](https://github.com/microsoft/sarif-pattern-matcher/commit/09d7506) Update test baselines.
- [256299e](https://github.com/microsoft/sarif-pattern-matcher/commit/256299e) Drop all unvalidated results to warning failure level.

## *v1.4.0-alpha-0017-g73383a0074*

- [73383a0](https://github.com/microsoft/sarif-pattern-matcher/commit/73383a0) Remove some security checks. Refine validation message processing. (#139)
- [178b74f](https://github.com/microsoft/sarif-pattern-matcher/commit/178b74f) Fixing azure function caching (#138)
- [7ed3a95](https://github.com/microsoft/sarif-pattern-matcher/commit/7ed3a95) Experiments with various OAUTH client id/secret pairs. (#137)
- [82d0aba](https://github.com/microsoft/sarif-pattern-matcher/commit/82d0aba) Gh fixes (#136)

## *v1.4.0-alpha-0013-gad991efd31*

- [ad991ef](https://github.com/microsoft/sarif-pattern-matcher/commit/ad991ef) Updating sarif-sdk submodule (#135)
- [8420c74](https://github.com/microsoft/sarif-pattern-matcher/commit/8420c74) Unknown host utility (#134)
- [cc73f56](https://github.com/microsoft/sarif-pattern-matcher/commit/cc73f56) Rule updates (#133)
- [98736b4](https://github.com/microsoft/sarif-pattern-matcher/commit/98736b4) Reuse FileRegionsCache (#132)
- [b28b068](https://github.com/microsoft/sarif-pattern-matcher/commit/b28b068) Fixing Cli not being a tool (#131)
- [727cc89](https://github.com/microsoft/sarif-pattern-matcher/commit/727cc89) Warnings (#130)
- [d7a4d0e](https://github.com/microsoft/sarif-pattern-matcher/commit/d7a4d0e) Aws credentials (#128)
- [5ff0d10](https://github.com/microsoft/sarif-pattern-matcher/commit/5ff0d10) Updating sarif-sdk submodule (#127)
- [4cbf043](https://github.com/microsoft/sarif-pattern-matcher/commit/4cbf043) Update validation message. (#126)
- [768382e](https://github.com/microsoft/sarif-pattern-matcher/commit/768382e) Enable NetAnalyzers (#125)

## *v1.4.0-alpha-0003-g463e567b02*

- [463e567](https://github.com/microsoft/sarif-pattern-matcher/commit/463e567) Fixing null reference in visitor (#124)

## *v1.4.0-alpha-0002-g995833e137*

- [995833e](https://github.com/microsoft/sarif-pattern-matcher/commit/995833e) Merge branch 'v1.3.1'
- [c85ac8e](https://github.com/microsoft/sarif-pattern-matcher/commit/c85ac8e) Set version to '1.4.0-alpha.{height}'
- [1bfe625](https://github.com/microsoft/sarif-pattern-matcher/commit/1bfe625) Set version to '1.3.1'
- [4ea9720](https://github.com/microsoft/sarif-pattern-matcher/commit/4ea9720) Fixing message not found when string isn't starting with upper case (#123)
- [1243fb9](https://github.com/microsoft/sarif-pattern-matcher/commit/1243fb9) Disable validator for specific rule (#122)
- [73046ed](https://github.com/microsoft/sarif-pattern-matcher/commit/73046ed) Adding e-mail fingerprint (#120)
- [46c040f](https://github.com/microsoft/sarif-pattern-matcher/commit/46c040f) Slack token validator (#119)
- [e4ea5c8](https://github.com/microsoft/sarif-pattern-matcher/commit/e4ea5c8) Do not emit empty fingerprint components. (#118)
- [088aaf6](https://github.com/microsoft/sarif-pattern-matcher/commit/088aaf6) Add elements to fingerprint. Increase visibility on shared code. (#117)
- [09fbc2c](https://github.com/microsoft/sarif-pattern-matcher/commit/09fbc2c) Shared strings and rule renames (#116)
- [bea3ae9](https://github.com/microsoft/sarif-pattern-matcher/commit/bea3ae9) Fixing missing shared strings file (#115)
- [1ac59b4](https://github.com/microsoft/sarif-pattern-matcher/commit/1ac59b4) Semicolon a separator for search defs files. Update binary files to include pack files. Use deny list for security rules. (#114)
- [38ac1ae](https://github.com/microsoft/sarif-pattern-matcher/commit/38ac1ae) Cli exports 3.1 only (#113)
- [1aa39b9](https://github.com/microsoft/sarif-pattern-matcher/commit/1aa39b9) Post scan validation (#112)
- [d62486a](https://github.com/microsoft/sarif-pattern-matcher/commit/d62486a) Enable net48 in Cli (#110)
- [d670bca](https://github.com/microsoft/sarif-pattern-matcher/commit/d670bca) Changing to maxvalue (#109)
- [1b8b0b3](https://github.com/microsoft/sarif-pattern-matcher/commit/1b8b0b3) Updating sarif-sdk submodule (#108)
- [a990758](https://github.com/microsoft/sarif-pattern-matcher/commit/a990758) Correct rule ids (make them opaque). Provide actual readable names. Plumb everything through. (#107)
- [fa3dc1c](https://github.com/microsoft/sarif-pattern-matcher/commit/fa3dc1c) fixing warnings and enable relative url (#105)
- [3281ee0](https://github.com/microsoft/sarif-pattern-matcher/commit/3281ee0) Update regex, add validator, add test cases, update expected output (#106)
- [55780aa](https://github.com/microsoft/sarif-pattern-matcher/commit/55780aa) Fixing duplicated id rules (#104)
- [e5af4e4](https://github.com/microsoft/sarif-pattern-matcher/commit/e5af4e4) Add SPAM fixes (#103)
- [22af480](https://github.com/microsoft/sarif-pattern-matcher/commit/22af480) Push data to match expressions (#101)
- [aad4bbd](https://github.com/microsoft/sarif-pattern-matcher/commit/aad4bbd) Adding more BannedApi (#99)
- [651734d](https://github.com/microsoft/sarif-pattern-matcher/commit/651734d) Filname won't be required (#102)
- [e00fdbc](https://github.com/microsoft/sarif-pattern-matcher/commit/e00fdbc) Adding more certificate validators (#98)
- [28319ba](https://github.com/microsoft/sarif-pattern-matcher/commit/28319ba) Adding unit tests for azure functions (#95)
- [aca0fa8](https://github.com/microsoft/sarif-pattern-matcher/commit/aca0fa8) Validate PFX files (#96)
- [7e4150b](https://github.com/microsoft/sarif-pattern-matcher/commit/7e4150b) Improving AzureFunctions and build project (#91)
- [ed3ef32](https://github.com/microsoft/sarif-pattern-matcher/commit/ed3ef32) Fixing tests search (#94)
- [0fd3072](https://github.com/microsoft/sarif-pattern-matcher/commit/0fd3072) Fixing regex search (#93)
- [c6ded7e](https://github.com/microsoft/sarif-pattern-matcher/commit/c6ded7e) improving build (#92)
- [d46e633](https://github.com/microsoft/sarif-pattern-matcher/commit/d46e633) Push data to match expressions (#90)
- [7901bae](https://github.com/microsoft/sarif-pattern-matcher/commit/7901bae) First draft version of working POC (#85)
- [27175a4](https://github.com/microsoft/sarif-pattern-matcher/commit/27175a4) Adding missing message to messageStrings (#86)
- [5463050](https://github.com/microsoft/sarif-pattern-matcher/commit/5463050) tweak host unknown message to report against resource. (#84)
- [0774f84](https://github.com/microsoft/sarif-pattern-matcher/commit/0774f84) Fix fingerprint emit. Fix unauthorized reporting. (#83)
- [f2df743](https://github.com/microsoft/sarif-pattern-matcher/commit/f2df743) Update SPAM
- [a38e18d](https://github.com/microsoft/sarif-pattern-matcher/commit/a38e18d) Fixing IndexOutOfRange Exception when we generate a message with space (#82)

## *v1.3.1-gdcccb00605*

- [dcccb00](https://github.com/microsoft/sarif-pattern-matcher/commit/dcccb00) updating to latest submodule (#81)
- [9772e91](https://github.com/microsoft/sarif-pattern-matcher/commit/9772e91) Fingerprints and multiline rules (#80)
- [b510fc2](https://github.com/microsoft/sarif-pattern-matcher/commit/b510fc2) Update SARIF submodule. (#79)
- [94a8d89](https://github.com/microsoft/sarif-pattern-matcher/commit/94a8d89) Fixing concurrency problem (#78)
- [32c5c06](https://github.com/microsoft/sarif-pattern-matcher/commit/32c5c06) Match refinement (#77)
- [aacaf0b](https://github.com/microsoft/sarif-pattern-matcher/commit/aacaf0b) Simplifying SearchSkimmer (#76)
- [6e667f9](https://github.com/microsoft/sarif-pattern-matcher/commit/6e667f9) Update SARIF SDK submodule. (#75)
- [237c2e7](https://github.com/microsoft/sarif-pattern-matcher/commit/237c2e7) Correct fingerprint regions (#73)
- [3e7c8b6](https://github.com/microsoft/sarif-pattern-matcher/commit/3e7c8b6) updated Markdown (#67)
- [6749887](https://github.com/microsoft/sarif-pattern-matcher/commit/6749887) Adjust failure level appropriately when dynamic validation is in play. (#71)
- [396ddcf](https://github.com/microsoft/sarif-pattern-matcher/commit/396ddcf) Update SPAM submodule (#70)
- [7b66039](https://github.com/microsoft/sarif-pattern-matcher/commit/7b66039) Add utilities class for validation plugins. (#69)
- [ed392d4](https://github.com/microsoft/sarif-pattern-matcher/commit/ed392d4) Adding System.Data.SqlClient to Cli project (#68)
- [63c3a09](https://github.com/microsoft/sarif-pattern-matcher/commit/63c3a09) Improve validation messages and provide groups information to validatiâ€¦ (#66)
- [dbc4063](https://github.com/microsoft/sarif-pattern-matcher/commit/dbc4063) Fact over theory (#65)
- [c202558](https://github.com/microsoft/sarif-pattern-matcher/commit/c202558) Update SARIF SDK submodule to 2.3.11 (#64)
- [6031eb2](https://github.com/microsoft/sarif-pattern-matcher/commit/6031eb2) Adding tests to RE2.Managed (#60)
- [d457b06](https://github.com/microsoft/sarif-pattern-matcher/commit/d457b06) When we build, package will generate .spam/Security folder with content (#59)
- [5bb636d](https://github.com/microsoft/sarif-pattern-matcher/commit/5bb636d) Update to newtonsoft 12.0.3 (#62)
- [5c41c13](https://github.com/microsoft/sarif-pattern-matcher/commit/5c41c13) Invalid for configured authorities (#61)

## *v1.3.1-g8d9ecb4e93*

- [63c3a09](https://github.com/microsoft/sarif-pattern-matcher/commit/63c3a09) Improve validation messages and provide groups information to validatiâ€¦ (#66)
- [dbc4063](https://github.com/microsoft/sarif-pattern-matcher/commit/dbc4063) Fact over theory (#65)
- [c202558](https://github.com/microsoft/sarif-pattern-matcher/commit/c202558) Update SARIF SDK submodule to 2.3.11 (#64)
- [6031eb2](https://github.com/microsoft/sarif-pattern-matcher/commit/6031eb2) Adding tests to RE2.Managed (#60)
- [d457b06](https://github.com/microsoft/sarif-pattern-matcher/commit/d457b06) When we build, package will generate .spam/Security folder with content (#59)
- [5bb636d](https://github.com/microsoft/sarif-pattern-matcher/commit/5bb636d) Update to newtonsoft 12.0.3 (#62)
- [5c41c13](https://github.com/microsoft/sarif-pattern-matcher/commit/5c41c13) Invalid for configured authorities (#61)

## *v1.3.1-g63c3a09ccf*

- [1243fb9](https://github.com/microsoft/sarif-pattern-matcher/commit/1243fb9) Disable validator for specific rule (#122)
- [73046ed](https://github.com/microsoft/sarif-pattern-matcher/commit/73046ed) Adding e-mail fingerprint (#120)
- [46c040f](https://github.com/microsoft/sarif-pattern-matcher/commit/46c040f) Slack token validator (#119)
- [e4ea5c8](https://github.com/microsoft/sarif-pattern-matcher/commit/e4ea5c8) Do not emit empty fingerprint components. (#118)
- [088aaf6](https://github.com/microsoft/sarif-pattern-matcher/commit/088aaf6) Add elements to fingerprint. Increase visibility on shared code. (#117)
- [09fbc2c](https://github.com/microsoft/sarif-pattern-matcher/commit/09fbc2c) Shared strings and rule renames (#116)
- [bea3ae9](https://github.com/microsoft/sarif-pattern-matcher/commit/bea3ae9) Fixing missing shared strings file (#115)
- [1ac59b4](https://github.com/microsoft/sarif-pattern-matcher/commit/1ac59b4) Semicolon a separator for search defs files. Update binary files to include pack files. Use deny list for security rules. (#114)
- [38ac1ae](https://github.com/microsoft/sarif-pattern-matcher/commit/38ac1ae) Cli exports 3.1 only (#113)
- [1aa39b9](https://github.com/microsoft/sarif-pattern-matcher/commit/1aa39b9) Post scan validation (#112)
- [d62486a](https://github.com/microsoft/sarif-pattern-matcher/commit/d62486a) Enable net48 in Cli (#110)
- [d670bca](https://github.com/microsoft/sarif-pattern-matcher/commit/d670bca) Changing to maxvalue (#109)
- [1b8b0b3](https://github.com/microsoft/sarif-pattern-matcher/commit/1b8b0b3) Updating sarif-sdk submodule (#108)
- [a990758](https://github.com/microsoft/sarif-pattern-matcher/commit/a990758) Correct rule ids (make them opaque). Provide actual readable names. Plumb everything through. (#107)
- [fa3dc1c](https://github.com/microsoft/sarif-pattern-matcher/commit/fa3dc1c) fixing warnings and enable relative url (#105)
- [3281ee0](https://github.com/microsoft/sarif-pattern-matcher/commit/3281ee0) Update regex, add validator, add test cases, update expected output (#106)
- [55780aa](https://github.com/microsoft/sarif-pattern-matcher/commit/55780aa) Fixing duplicated id rules (#104)
- [e5af4e4](https://github.com/microsoft/sarif-pattern-matcher/commit/e5af4e4) Add SPAM fixes (#103)
- [22af480](https://github.com/microsoft/sarif-pattern-matcher/commit/22af480) Push data to match expressions (#101)
- [aad4bbd](https://github.com/microsoft/sarif-pattern-matcher/commit/aad4bbd) Adding more BannedApi (#99)
- [651734d](https://github.com/microsoft/sarif-pattern-matcher/commit/651734d) Filname won't be required (#102)
- [e00fdbc](https://github.com/microsoft/sarif-pattern-matcher/commit/e00fdbc) Adding more certificate validators (#98)
- [28319ba](https://github.com/microsoft/sarif-pattern-matcher/commit/28319ba) Adding unit tests for azure functions (#95)
- [aca0fa8](https://github.com/microsoft/sarif-pattern-matcher/commit/aca0fa8) Validate PFX files (#96)
- [7e4150b](https://github.com/microsoft/sarif-pattern-matcher/commit/7e4150b) Improving AzureFunctions and build project (#91)
- [ed3ef32](https://github.com/microsoft/sarif-pattern-matcher/commit/ed3ef32) Fixing tests search (#94)
- [0fd3072](https://github.com/microsoft/sarif-pattern-matcher/commit/0fd3072) Fixing regex search (#93)
- [c6ded7e](https://github.com/microsoft/sarif-pattern-matcher/commit/c6ded7e) improving build (#92)
- [d46e633](https://github.com/microsoft/sarif-pattern-matcher/commit/d46e633) Push data to match expressions (#90)
- [7901bae](https://github.com/microsoft/sarif-pattern-matcher/commit/7901bae) First draft version of working POC (#85)
- [27175a4](https://github.com/microsoft/sarif-pattern-matcher/commit/27175a4) Adding missing message to messageStrings (#86)
- [5463050](https://github.com/microsoft/sarif-pattern-matcher/commit/5463050) tweak host unknown message to report against resource. (#84)
- [0774f84](https://github.com/microsoft/sarif-pattern-matcher/commit/0774f84) Fix fingerprint emit. Fix unauthorized reporting. (#83)
- [f2df743](https://github.com/microsoft/sarif-pattern-matcher/commit/f2df743) Update SPAM
- [a38e18d](https://github.com/microsoft/sarif-pattern-matcher/commit/a38e18d) Fixing IndexOutOfRange Exception when we generate a message with space (#82)
- [dcccb00](https://github.com/microsoft/sarif-pattern-matcher/commit/dcccb00) updating to latest submodule (#81)
- [9772e91](https://github.com/microsoft/sarif-pattern-matcher/commit/9772e91) Fingerprints and multiline rules (#80)
- [b510fc2](https://github.com/microsoft/sarif-pattern-matcher/commit/b510fc2) Update SARIF submodule. (#79)
- [94a8d89](https://github.com/microsoft/sarif-pattern-matcher/commit/94a8d89) Fixing concurrency problem (#78)
- [32c5c06](https://github.com/microsoft/sarif-pattern-matcher/commit/32c5c06) Match refinement (#77)
- [aacaf0b](https://github.com/microsoft/sarif-pattern-matcher/commit/aacaf0b) Simplifying SearchSkimmer (#76)
- [6e667f9](https://github.com/microsoft/sarif-pattern-matcher/commit/6e667f9) Update SARIF SDK submodule. (#75)
- [237c2e7](https://github.com/microsoft/sarif-pattern-matcher/commit/237c2e7) Correct fingerprint regions (#73)
- [3e7c8b6](https://github.com/microsoft/sarif-pattern-matcher/commit/3e7c8b6) updated Markdown (#67)
- [6749887](https://github.com/microsoft/sarif-pattern-matcher/commit/6749887) Adjust failure level appropriately when dynamic validation is in play. (#71)
- [396ddcf](https://github.com/microsoft/sarif-pattern-matcher/commit/396ddcf) Update SPAM submodule (#70)
- [7b66039](https://github.com/microsoft/sarif-pattern-matcher/commit/7b66039) Add utilities class for validation plugins. (#69)
- [ed392d4](https://github.com/microsoft/sarif-pattern-matcher/commit/ed392d4) Adding System.Data.SqlClient to Cli project (#68)

## *v1.3.1-beta-0028-g1243fb9249*

- [1243fb9](https://github.com/microsoft/sarif-pattern-matcher/commit/1243fb9) Disable validator for specific rule (#122)

## *v1.3.1-beta-0027-g73046edd74*

- [73046ed](https://github.com/microsoft/sarif-pattern-matcher/commit/73046ed) Adding e-mail fingerprint (#120)
- [46c040f](https://github.com/microsoft/sarif-pattern-matcher/commit/46c040f) Slack token validator (#119)
- [e4ea5c8](https://github.com/microsoft/sarif-pattern-matcher/commit/e4ea5c8) Do not emit empty fingerprint components. (#118)
- [088aaf6](https://github.com/microsoft/sarif-pattern-matcher/commit/088aaf6) Add elements to fingerprint. Increase visibility on shared code. (#117)
- [09fbc2c](https://github.com/microsoft/sarif-pattern-matcher/commit/09fbc2c) Shared strings and rule renames (#116)
- [bea3ae9](https://github.com/microsoft/sarif-pattern-matcher/commit/bea3ae9) Fixing missing shared strings file (#115)
- [1ac59b4](https://github.com/microsoft/sarif-pattern-matcher/commit/1ac59b4) Semicolon a separator for search defs files. Update binary files to include pack files. Use deny list for security rules. (#114)
- [38ac1ae](https://github.com/microsoft/sarif-pattern-matcher/commit/38ac1ae) Cli exports 3.1 only (#113)
- [1aa39b9](https://github.com/microsoft/sarif-pattern-matcher/commit/1aa39b9) Post scan validation (#112)
- [d62486a](https://github.com/microsoft/sarif-pattern-matcher/commit/d62486a) Enable net48 in Cli (#110)
- [d670bca](https://github.com/microsoft/sarif-pattern-matcher/commit/d670bca) Changing to maxvalue (#109)
- [1b8b0b3](https://github.com/microsoft/sarif-pattern-matcher/commit/1b8b0b3) Updating sarif-sdk submodule (#108)
- [a990758](https://github.com/microsoft/sarif-pattern-matcher/commit/a990758) Correct rule ids (make them opaque). Provide actual readable names. Plumb everything through. (#107)
- [fa3dc1c](https://github.com/microsoft/sarif-pattern-matcher/commit/fa3dc1c) fixing warnings and enable relative url (#105)
- [3281ee0](https://github.com/microsoft/sarif-pattern-matcher/commit/3281ee0) Update regex, add validator, add test cases, update expected output (#106)
- [55780aa](https://github.com/microsoft/sarif-pattern-matcher/commit/55780aa) Fixing duplicated id rules (#104)
- [e5af4e4](https://github.com/microsoft/sarif-pattern-matcher/commit/e5af4e4) Add SPAM fixes (#103)
- [22af480](https://github.com/microsoft/sarif-pattern-matcher/commit/22af480) Push data to match expressions (#101)
- [aad4bbd](https://github.com/microsoft/sarif-pattern-matcher/commit/aad4bbd) Adding more BannedApi (#99)
- [651734d](https://github.com/microsoft/sarif-pattern-matcher/commit/651734d) Filname won't be required (#102)
- [e00fdbc](https://github.com/microsoft/sarif-pattern-matcher/commit/e00fdbc) Adding more certificate validators (#98)
- [28319ba](https://github.com/microsoft/sarif-pattern-matcher/commit/28319ba) Adding unit tests for azure functions (#95)
- [aca0fa8](https://github.com/microsoft/sarif-pattern-matcher/commit/aca0fa8) Validate PFX files (#96)
- [7e4150b](https://github.com/microsoft/sarif-pattern-matcher/commit/7e4150b) Improving AzureFunctions and build project (#91)
- [ed3ef32](https://github.com/microsoft/sarif-pattern-matcher/commit/ed3ef32) Fixing tests search (#94)
- [0fd3072](https://github.com/microsoft/sarif-pattern-matcher/commit/0fd3072) Fixing regex search (#93)
- [c6ded7e](https://github.com/microsoft/sarif-pattern-matcher/commit/c6ded7e) improving build (#92)
- [d46e633](https://github.com/microsoft/sarif-pattern-matcher/commit/d46e633) Push data to match expressions (#90)
- [7901bae](https://github.com/microsoft/sarif-pattern-matcher/commit/7901bae) First draft version of working POC (#85)
- [27175a4](https://github.com/microsoft/sarif-pattern-matcher/commit/27175a4) Adding missing message to messageStrings (#86)
- [5463050](https://github.com/microsoft/sarif-pattern-matcher/commit/5463050) tweak host unknown message to report against resource. (#84)
- [0774f84](https://github.com/microsoft/sarif-pattern-matcher/commit/0774f84) Fix fingerprint emit. Fix unauthorized reporting. (#83)
- [f2df743](https://github.com/microsoft/sarif-pattern-matcher/commit/f2df743) Update SPAM
- [a38e18d](https://github.com/microsoft/sarif-pattern-matcher/commit/a38e18d) Fixing IndexOutOfRange Exception when we generate a message with space (#82)
- [dcccb00](https://github.com/microsoft/sarif-pattern-matcher/commit/dcccb00) updating to latest submodule (#81)
- [9772e91](https://github.com/microsoft/sarif-pattern-matcher/commit/9772e91) Fingerprints and multiline rules (#80)
- [b510fc2](https://github.com/microsoft/sarif-pattern-matcher/commit/b510fc2) Update SARIF submodule. (#79)
- [94a8d89](https://github.com/microsoft/sarif-pattern-matcher/commit/94a8d89) Fixing concurrency problem (#78)
- [32c5c06](https://github.com/microsoft/sarif-pattern-matcher/commit/32c5c06) Match refinement (#77)
- [aacaf0b](https://github.com/microsoft/sarif-pattern-matcher/commit/aacaf0b) Simplifying SearchSkimmer (#76)
- [6e667f9](https://github.com/microsoft/sarif-pattern-matcher/commit/6e667f9) Update SARIF SDK submodule. (#75)
- [237c2e7](https://github.com/microsoft/sarif-pattern-matcher/commit/237c2e7) Correct fingerprint regions (#73)
- [3e7c8b6](https://github.com/microsoft/sarif-pattern-matcher/commit/3e7c8b6) updated Markdown (#67)
- [6749887](https://github.com/microsoft/sarif-pattern-matcher/commit/6749887) Adjust failure level appropriately when dynamic validation is in play. (#71)
- [396ddcf](https://github.com/microsoft/sarif-pattern-matcher/commit/396ddcf) Update SPAM submodule (#70)
- [7b66039](https://github.com/microsoft/sarif-pattern-matcher/commit/7b66039) Add utilities class for validation plugins. (#69)
- [ed392d4](https://github.com/microsoft/sarif-pattern-matcher/commit/ed392d4) Adding System.Data.SqlClient to Cli project (#68)
- [63c3a09](https://github.com/microsoft/sarif-pattern-matcher/commit/63c3a09) Improve validation messages and provide groups information to validatiâ€¦ (#66)
- [dbc4063](https://github.com/microsoft/sarif-pattern-matcher/commit/dbc4063) Fact over theory (#65)
- [c202558](https://github.com/microsoft/sarif-pattern-matcher/commit/c202558) Update SARIF SDK submodule to 2.3.11 (#64)
- [6031eb2](https://github.com/microsoft/sarif-pattern-matcher/commit/6031eb2) Adding tests to RE2.Managed (#60)
- [d457b06](https://github.com/microsoft/sarif-pattern-matcher/commit/d457b06) When we build, package will generate .spam/Security folder with content (#59)
- [5bb636d](https://github.com/microsoft/sarif-pattern-matcher/commit/5bb636d) Update to newtonsoft 12.0.3 (#62)
- [5c41c13](https://github.com/microsoft/sarif-pattern-matcher/commit/5c41c13) Invalid for configured authorities (#61)
- [8d9ecb4](https://github.com/microsoft/sarif-pattern-matcher/commit/8d9ecb4) Fixing RE2.Managed package (#57)

## *v1.3.0-gc0d20f77f8*

- [c0d20f7](https://github.com/microsoft/sarif-pattern-matcher/commit/c0d20f7) Update SARIF-SDK (#56)
- [3adcfdd](https://github.com/microsoft/sarif-pattern-matcher/commit/3adcfdd) Updating properties and version.json (#55)

## *v1.0.0-g26af518ec3*

- [26af518](https://github.com/microsoft/sarif-pattern-matcher/commit/26af518) Fixing security target (#54)
