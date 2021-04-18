#pragma once
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once
#pragma pack(push, 1)

#include <cstdint>

struct alignas(1) Submatch {
	uint64_t Index;
	uint64_t Length;
};

#pragma pack(pop)