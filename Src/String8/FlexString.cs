// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.CodeAnalysis.SarifPatternMatcher.Strings
{
    /// <summary>
    ///  FlexString can contain a String (UTF-16), String8 (UTF-8), or both.
    ///  If conversion is required, value is converted and cached.
    /// </summary>
    public class FlexString : IComparable<FlexString>, IEquatable<FlexString>
    {
        private bool _isStringAvailable;
        private bool _isString8Available;
        private string _string;
        private String8 _string8;

        /// <summary>
        ///  Construct a FlexString from a string value
        /// </summary>
        /// <param name="value">string value to wrap</param>
        public FlexString(string value)
        {
            _string = value;
            _isStringAvailable = true;
        }

        /// <summary>
        ///  Construct a FlexString from a String8 value
        /// </summary>
        /// <param name="value">String8 value to wrap</param>
        public FlexString(String8 value)
        {
            _string8 = value;
            _isString8Available = true;
        }

        public static implicit operator FlexString(string value)
        {
            return new FlexString(value);
        }

        public static implicit operator FlexString(String8 value8)
        {
            return new FlexString(value8);
        }

        public static implicit operator string(FlexString value)
        {
            return value?.String ?? null;
        }

        public static implicit operator String8(FlexString value)
        {
            return value?.String8 ?? String8.Empty;
        }

        public static bool IsNullOrEmpty(FlexString value)
        {
            return value == null || (value._isString8Available ? value._string8.IsEmpty : string.IsNullOrEmpty(value._string));
        }

        public static bool IsNull(FlexString value)
        {
            return value == null || (value._isStringAvailable && value._string == null);
        }

        /// <summary>
        ///  Get the .NET String (UTF-16 string) representation of this FlexString.
        /// </summary>
        public string String
        {
            get
            {
                if (!_isStringAvailable)
                {
                    _string = _string8.ToString();
                    _isStringAvailable = true;
                }

                return _string;
            }
        }

        /// <summary>
        ///  Get the String8 (UTF-8 string) representation of this FlexString.
        /// </summary>
        public String8 String8
        {
            get
            {
                if (!_isString8Available)
                {
                    _string8 = String8.ConvertExpensively(_string);
                    _isString8Available = true;
                }

                return _string8;
            }
        }

        /// <summary>
        ///  Compare two FlexStrings and return which should sort first,
        ///  using Ordinal comparison.
        /// </summary>
        /// <param name="other">FlexString to compare to</param>
        /// <returns>Negative if this instance sorts first, positive if this instance sorts later</returns>
        public int CompareTo(FlexString other)
        {
            return this._isString8Available && other._isString8Available
                ? this.String8.CompareTo(other.String8)
                : string.CompareOrdinal(this.String, other.String);
        }

        /// <summary>
        ///  Return whether two FlexStrings are equal (Ordinal)
        /// </summary>
        /// <param name="other">FlexString to compare to</param>
        /// <returns>True if strings Equal; False otherwise</returns>
        public bool Equals(FlexString other)
        {
            return this.CompareTo(other) == 0;
        }

        /// <summary>
        ///  Get the .NET string representation of this FlexString.
        /// </summary>
        /// <returns>String value of this FlexString</returns>
        public override string ToString()
        {
            return this.String;
        }
    }
}
