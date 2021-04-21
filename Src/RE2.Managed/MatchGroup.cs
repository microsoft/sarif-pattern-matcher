// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.RE2.Managed
{
    public enum MatchGroupType
    {
        /// <summary>
        /// todo
        /// </summary>
        Full,

        /// <summary>
        /// todo
        /// </summary>
        Named,

        /// <summary>
        /// todo
        /// </summary>
        Anonymous,
    }

    public class MatchGroup
    {
        public MatchGroup(MatchGroupType matchGroupType, string text)
        {
            this.MatchGroupType = matchGroupType;
            this.GroupName = null;
            this.Text = text;
        }

        public MatchGroup(MatchGroupType matchGroupType, string groupName, string text)
        {
            this.MatchGroupType = matchGroupType;
            this.GroupName = groupName;
            this.Text = text;
        }

        public MatchGroupType MatchGroupType { get; private set; }

        public string GroupName { get; private set; }

        public string Text { get; private set; }

        public override bool Equals(object obj)
        {
            return Equals(obj as MatchGroup);
        }

        public bool Equals(MatchGroup other)
        {
            return other != null &&
                MatchGroupType == other.MatchGroupType &&
                GroupName == other.GroupName &&
                Text == other.Text;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(MatchGroupType, GroupName, Text);
        }
    }
}
