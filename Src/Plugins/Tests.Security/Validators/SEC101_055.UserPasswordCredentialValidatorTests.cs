// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class UserPasswordCredentialValidatorTests
    {
        private const string expectedValidationState = nameof(ValidationState.Unauthorized);
        private const string username = "username1@microsoft.com";
        private const string password = "Doodle_BLOB1";

        [Fact]
        public void InvalidCredentials_ShouldBeUnauthorized()
        {
            UserPasswordCredentialValidator validator = new UserPasswordCredentialValidator();
            string fingerprintText = $"[acct={username}][pwd={password}]";
            string message = null;
            string actualValidationState = UserPasswordCredentialValidator.IsValidDynamic(ref fingerprintText, ref message);
            Assert.Equal(expectedValidationState, actualValidationState);
        }
    }
}
