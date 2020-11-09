// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once
#pragma pack(push, 1)

// Represents a block of UTF8 text in a slice of a byte array.
// Matches RE2.Managed\String8.cs and must maintain identical layout.
struct String8 {
	char* Array;
	__int32 Index;
	__int32 Length;
};

#pragma pack(pop)