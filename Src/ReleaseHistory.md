# Release History

## *v1.4.0-alpha-0044-gee1e18ea36*

- ee1e18e Adding limits to SQL regex (#167)
- 5875545 updating contributing with more guidelines (#166)
- 09ef181 Remove ordering in MySql regex (#165)
- baef865 Ignore pattern if contains tree (#164)
- 25f3c35 Fixing connection string for sql (#163)
- f0c517c Return NoMatch if matchedPattern contains usercontent (#162)

## *v1.4.0-alpha-0038-g669bacd87a*

- 669bacd Make PostgreSQL validator order-insensitive (#159)
- af4c6e0 Order-insensitive for SQL connections (#160)
- 8eb24df Improving GitHub PAT search (#161)

## *v1.4.0-alpha-0035-g4196919fb1*

- 4196919 Renaming ids and fixing Octokit publish (#158)
- a4b0410 PostgreSql Connection String Validator (#157)
- 964318c Add general Newtonsoft binding redirect. (#156)

## *v1.4.0-alpha-0032-g2224b0944a*

- 2224b09 MySql improvements (#155)
- a0fecf6 Ignore expired creds (no dynamic validation. (#153)
- 74bff7b SqlConnectionString validator (#154)
- a9aa7cf trying to improve build time (#152)
- d3a1e9b Azure Database for MySQL validator (#151)
- dbff24e Gh noise reduction (#150)
- 1dc67ee Avoid null deref in unknown host exception handling code. (#149)
- f8be8b2 upgrading coverlet package (#148)

## *v1.4.0-alpha-0024-g3cab78cc0d*

- 3cab78c Clean up exception reporting utility code. (#147)
- 5f68769 Google API key validator. (#146)
- 7e76c4b Simplify pat fingerprint name (#145)
- f9c212e Creating test pattern (#141)
- 40d635d Fixing build code coverage (#144)
- 3cf5aba Reading assemblies before loading (#143)
- ddbe027 Allow for flowing rule properties to rules. (#142)
- 73383a0 Remove some security checks. Refine validation message processing. (#139)
- 178b74f Fixing azure function caching (#138)
- 7ed3a95 Experiments with various OAUTH client id/secret pairs. (#137)
- 82d0aba Gh fixes (#136)
- ad991ef Updating sarif-sdk submodule (#135)
- 8420c74 Unknown host utility (#134)
- e58a09e Update SARIF submodule.
- 691a212 Merge remote-tracking branch 'origin/main' into unknown-host-utility
- 26da762 Update unknown host handler.
- 08f6962 Improve negative condition reporting in various rules.
- 2189ea1 Merge remote-tracking branch 'origin/main' into rule-updates
- 09d7506 Update test baselines.
- 256299e Drop all unvalidated results to warning failure level.

## *v1.4.0-alpha-0019-g3cf5aba708*

- 73383a0 Remove some security checks. Refine validation message processing. (#139)
- 178b74f Fixing azure function caching (#138)
- 7ed3a95 Experiments with various OAUTH client id/secret pairs. (#137)
- 82d0aba Gh fixes (#136)
- ad991ef Updating sarif-sdk submodule (#135)
- 8420c74 Unknown host utility (#134)
- e58a09e Update SARIF submodule.
- 691a212 Merge remote-tracking branch 'origin/main' into unknown-host-utility
- 26da762 Update unknown host handler.
- 08f6962 Improve negative condition reporting in various rules.
- 2189ea1 Merge remote-tracking branch 'origin/main' into rule-updates
- 09d7506 Update test baselines.
- 256299e Drop all unvalidated results to warning failure level.

## *v1.4.0-alpha-0017-g73383a0074*

- 73383a0 Remove some security checks. Refine validation message processing. (#139)
- 178b74f Fixing azure function caching (#138)
- 7ed3a95 Experiments with various OAUTH client id/secret pairs. (#137)
- 82d0aba Gh fixes (#136)

## *v1.4.0-alpha-0013-gad991efd31*

- ad991ef Updating sarif-sdk submodule (#135)
- 8420c74 Unknown host utility (#134)
- cc73f56 Rule updates (#133)
- 98736b4 Reuse FileRegionsCache (#132)
- b28b068 Fixing Cli not being a tool (#131)
- 727cc89 Warnings (#130)
- d7a4d0e Aws credentials (#128)
- 5ff0d10 Updating sarif-sdk submodule (#127)
- 4cbf043 Update validation message. (#126)
- 768382e Enable NetAnalyzers (#125)

## *v1.4.0-alpha-0003-g463e567b02*

- 463e567 Fixing null reference in visitor (#124)

## *v1.4.0-alpha-0002-g995833e137*

- 995833e Merge branch 'v1.3.1'
- c85ac8e Set version to '1.4.0-alpha.{height}'
- 1bfe625 Set version to '1.3.1'
- 4ea9720 Fixing message not found when string isn't starting with upper case (#123)
- 1243fb9 Disable validator for specific rule (#122)
- 73046ed Adding e-mail fingerprint (#120)
- 46c040f Slack token validator (#119)
- e4ea5c8 Do not emit empty fingerprint components. (#118)
- 088aaf6 Add elements to fingerprint. Increase visibility on shared code. (#117)
- 09fbc2c Shared strings and rule renames (#116)
- bea3ae9 Fixing missing shared strings file (#115)
- 1ac59b4 Semicolon a separator for search defs files. Update binary files to include pack files. Use deny list for security rules. (#114)
- 38ac1ae Cli exports 3.1 only (#113)
- 1aa39b9 Post scan validation (#112)
- d62486a Enable net48 in Cli (#110)
- d670bca Changing to maxvalue (#109)
- 1b8b0b3 Updating sarif-sdk submodule (#108)
- a990758 Correct rule ids (make them opaque). Provide actual readable names. Plumb everything through. (#107)
- fa3dc1c fixing warnings and enable relative url (#105)
- 3281ee0 Update regex, add validator, add test cases, update expected output (#106)
- 55780aa Fixing duplicated id rules (#104)
- e5af4e4 Add SPAM fixes (#103)
- 22af480 Push data to match expressions (#101)
- aad4bbd Adding more BannedApi (#99)
- 651734d Filname won't be required (#102)
- e00fdbc Adding more certificate validators (#98)
- 28319ba Adding unit tests for azure functions (#95)
- aca0fa8 Validate PFX files (#96)
- 7e4150b Improving AzureFunctions and build project (#91)
- ed3ef32 Fixing tests search (#94)
- 0fd3072 Fixing regex search (#93)
- c6ded7e improving build (#92)
- d46e633 Push data to match expressions (#90)
- 7901bae First draft version of working POC (#85)
- 27175a4 Adding missing message to messageStrings (#86)
- 5463050 tweak host unknown message to report against resource. (#84)
- 0774f84 Fix fingerprint emit. Fix unauthorized reporting. (#83)
- f2df743 Update SPAM
- a38e18d Fixing IndexOutOfRange Exception when we generate a message with space (#82)

## *v1.3.1-gdcccb00605*

- dcccb00 updating to latest submodule (#81)
- 9772e91 Fingerprints and multiline rules (#80)
- b510fc2 Update SARIF submodule. (#79)
- 94a8d89 Fixing concurrency problem (#78)
- 32c5c06 Match refinement (#77)
- aacaf0b Simplifying SearchSkimmer (#76)
- 6e667f9 Update SARIF SDK submodule. (#75)
- 237c2e7 Correct fingerprint regions (#73)
- 3e7c8b6 updated Markdown (#67)
- 6749887 Adjust failure level appropriately when dynamic validation is in play. (#71)
- 396ddcf Update SPAM submodule (#70)
- 7b66039 Add utilities class for validation plugins. (#69)
- ed392d4 Adding System.Data.SqlClient to Cli project (#68)
- 63c3a09 Improve validation messages and provide groups information to validatiâ€¦ (#66)
- dbc4063 Fact over theory (#65)
- c202558 Update SARIF SDK submodule to 2.3.11 (#64)
- 6031eb2 Adding tests to RE2.Managed (#60)
- d457b06 When we build, package will generate .spam/Security folder with content (#59)
- 5bb636d Update to newtonsoft 12.0.3 (#62)
- 5c41c13 Invalid for configured authorities (#61)

## *v1.3.1-g8d9ecb4e93*

- 63c3a09 Improve validation messages and provide groups information to validatiâ€¦ (#66)
- dbc4063 Fact over theory (#65)
- c202558 Update SARIF SDK submodule to 2.3.11 (#64)
- 6031eb2 Adding tests to RE2.Managed (#60)
- d457b06 When we build, package will generate .spam/Security folder with content (#59)
- 5bb636d Update to newtonsoft 12.0.3 (#62)
- 5c41c13 Invalid for configured authorities (#61)

## *v1.3.1-g63c3a09ccf*

- 1243fb9 Disable validator for specific rule (#122)
- 73046ed Adding e-mail fingerprint (#120)
- 46c040f Slack token validator (#119)
- e4ea5c8 Do not emit empty fingerprint components. (#118)
- 088aaf6 Add elements to fingerprint. Increase visibility on shared code. (#117)
- 09fbc2c Shared strings and rule renames (#116)
- bea3ae9 Fixing missing shared strings file (#115)
- 1ac59b4 Semicolon a separator for search defs files. Update binary files to include pack files. Use deny list for security rules. (#114)
- 38ac1ae Cli exports 3.1 only (#113)
- 1aa39b9 Post scan validation (#112)
- d62486a Enable net48 in Cli (#110)
- d670bca Changing to maxvalue (#109)
- 1b8b0b3 Updating sarif-sdk submodule (#108)
- a990758 Correct rule ids (make them opaque). Provide actual readable names. Plumb everything through. (#107)
- fa3dc1c fixing warnings and enable relative url (#105)
- 3281ee0 Update regex, add validator, add test cases, update expected output (#106)
- 55780aa Fixing duplicated id rules (#104)
- e5af4e4 Add SPAM fixes (#103)
- 22af480 Push data to match expressions (#101)
- aad4bbd Adding more BannedApi (#99)
- 651734d Filname won't be required (#102)
- e00fdbc Adding more certificate validators (#98)
- 28319ba Adding unit tests for azure functions (#95)
- aca0fa8 Validate PFX files (#96)
- 7e4150b Improving AzureFunctions and build project (#91)
- ed3ef32 Fixing tests search (#94)
- 0fd3072 Fixing regex search (#93)
- c6ded7e improving build (#92)
- d46e633 Push data to match expressions (#90)
- 7901bae First draft version of working POC (#85)
- 27175a4 Adding missing message to messageStrings (#86)
- 5463050 tweak host unknown message to report against resource. (#84)
- 0774f84 Fix fingerprint emit. Fix unauthorized reporting. (#83)
- f2df743 Update SPAM
- a38e18d Fixing IndexOutOfRange Exception when we generate a message with space (#82)
- dcccb00 updating to latest submodule (#81)
- 9772e91 Fingerprints and multiline rules (#80)
- b510fc2 Update SARIF submodule. (#79)
- 94a8d89 Fixing concurrency problem (#78)
- 32c5c06 Match refinement (#77)
- aacaf0b Simplifying SearchSkimmer (#76)
- 6e667f9 Update SARIF SDK submodule. (#75)
- 237c2e7 Correct fingerprint regions (#73)
- 3e7c8b6 updated Markdown (#67)
- 6749887 Adjust failure level appropriately when dynamic validation is in play. (#71)
- 396ddcf Update SPAM submodule (#70)
- 7b66039 Add utilities class for validation plugins. (#69)
- ed392d4 Adding System.Data.SqlClient to Cli project (#68)

## *v1.3.1-beta-0028-g1243fb9249*

- 1243fb9 Disable validator for specific rule (#122)

## *v1.3.1-beta-0027-g73046edd74*

- 73046ed Adding e-mail fingerprint (#120)
- 46c040f Slack token validator (#119)
- e4ea5c8 Do not emit empty fingerprint components. (#118)
- 088aaf6 Add elements to fingerprint. Increase visibility on shared code. (#117)
- 09fbc2c Shared strings and rule renames (#116)
- bea3ae9 Fixing missing shared strings file (#115)
- 1ac59b4 Semicolon a separator for search defs files. Update binary files to include pack files. Use deny list for security rules. (#114)
- 38ac1ae Cli exports 3.1 only (#113)
- 1aa39b9 Post scan validation (#112)
- d62486a Enable net48 in Cli (#110)
- d670bca Changing to maxvalue (#109)
- 1b8b0b3 Updating sarif-sdk submodule (#108)
- a990758 Correct rule ids (make them opaque). Provide actual readable names. Plumb everything through. (#107)
- fa3dc1c fixing warnings and enable relative url (#105)
- 3281ee0 Update regex, add validator, add test cases, update expected output (#106)
- 55780aa Fixing duplicated id rules (#104)
- e5af4e4 Add SPAM fixes (#103)
- 22af480 Push data to match expressions (#101)
- aad4bbd Adding more BannedApi (#99)
- 651734d Filname won't be required (#102)
- e00fdbc Adding more certificate validators (#98)
- 28319ba Adding unit tests for azure functions (#95)
- aca0fa8 Validate PFX files (#96)
- 7e4150b Improving AzureFunctions and build project (#91)
- ed3ef32 Fixing tests search (#94)
- 0fd3072 Fixing regex search (#93)
- c6ded7e improving build (#92)
- d46e633 Push data to match expressions (#90)
- 7901bae First draft version of working POC (#85)
- 27175a4 Adding missing message to messageStrings (#86)
- 5463050 tweak host unknown message to report against resource. (#84)
- 0774f84 Fix fingerprint emit. Fix unauthorized reporting. (#83)
- f2df743 Update SPAM
- a38e18d Fixing IndexOutOfRange Exception when we generate a message with space (#82)
- dcccb00 updating to latest submodule (#81)
- 9772e91 Fingerprints and multiline rules (#80)
- b510fc2 Update SARIF submodule. (#79)
- 94a8d89 Fixing concurrency problem (#78)
- 32c5c06 Match refinement (#77)
- aacaf0b Simplifying SearchSkimmer (#76)
- 6e667f9 Update SARIF SDK submodule. (#75)
- 237c2e7 Correct fingerprint regions (#73)
- 3e7c8b6 updated Markdown (#67)
- 6749887 Adjust failure level appropriately when dynamic validation is in play. (#71)
- 396ddcf Update SPAM submodule (#70)
- 7b66039 Add utilities class for validation plugins. (#69)
- ed392d4 Adding System.Data.SqlClient to Cli project (#68)
- 63c3a09 Improve validation messages and provide groups information to validatiâ€¦ (#66)
- dbc4063 Fact over theory (#65)
- c202558 Update SARIF SDK submodule to 2.3.11 (#64)
- 6031eb2 Adding tests to RE2.Managed (#60)
- d457b06 When we build, package will generate .spam/Security folder with content (#59)
- 5bb636d Update to newtonsoft 12.0.3 (#62)
- 5c41c13 Invalid for configured authorities (#61)
- 8d9ecb4 Fixing RE2.Managed package (#57)

## *v1.3.0-gc0d20f77f8*

- c0d20f7 Update SARIF-SDK (#56)
- 3adcfdd Updating properties and version.json (#55)

## *v1.0.0-g26af518ec3*

- 26af518 Fixing security target (#54)
