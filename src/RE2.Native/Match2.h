// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once
#pragma pack(push, 1)

// Represents the UTF8 position and length of a Regular Expression match within text.
// Matches RE2.Managed\Match2.cs and must maintain identical layout.
struct Match2 {
	__int32 Index;
	__int32 Length;
};
#pragma pack(pop)