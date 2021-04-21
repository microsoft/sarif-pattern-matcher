#pragma once
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once
#pragma pack(push, 1)

#include <cstdint>

struct alignas(1) StringUtf8 {
	uint8_t* Bytes;
	int32_t Length;
};

#pragma pack(pop)
