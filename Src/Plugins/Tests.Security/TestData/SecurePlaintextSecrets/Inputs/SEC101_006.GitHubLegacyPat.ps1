# ************ Below caught in $SEC101/006.GitHubLegacyPat

# Xml style
<GithubToken>
	ff34885a8624460a855540c6592698d2f1812843
</GithubToken>

# AppSettings style
<appSettings>
  <add key="GitHubLegacyPat" value="dead885a8624460a855540c6592698d2f1812843" />
</appSettings>

# Code style
var myGitHubPersonalAccessToken = "ff34885a8624460a855540c6592698d2f181dead";

# Link style
# This should trigger, but it should report as NoMatch
https://github.com/microsoft/sarif-pattern-matcher/commit/4196919fb12cc4aa8ec0159a746c1e03b4ffa89c
https://avatars0.githubusercontent.com/u/16199012?u=4196919fb12cc4aa8ec0159a746c1e03b4ffa89c&v=4
https://github.com/microsoft/sarif-pattern-matcher/tree/7af498925c89a9e8c07fb8a65223e89d513d4eea

# This should trigger, but it should report as NoMatch
GitHubTriggersShouldReturnBothSourceRepoAndPullRequestTriggers

# ************ Below caught in $SEC101/006.GitHubPat_2021_04_05

# Personal access token
ghp_000000000001234567890123456789012345

# Refresh token
ghr_111111111101234567890123456789012345