using System;
using System.Collections.Generic;
using System.Text;

using Xunit;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher.Plugins.Security.Validators
{
    public class AlibabaAccessKeyValidatorTests : AlibabaAccessKeyValidator
    {
        private readonly string _expectedValidationState = nameof(ValidationState.NoMatch);
        private readonly string _accessKeyId = "LTAI01234567890123456789";
        private readonly string _accessKeySecret = "111111111101234567890123456789";

        [Fact]
        public void DummyCredentials_ShouldHaveInvalidTest()
        {
            string fingerprintText = string.Format("[acct={0}][pwd={1}]", _accessKeyId, _accessKeySecret);
            string message = null;
            string actualValidationState = IsValidDynamicHelper(ref fingerprintText, ref message);
            Assert.Equal(_expectedValidationState, actualValidationState);
        }
    }
}
