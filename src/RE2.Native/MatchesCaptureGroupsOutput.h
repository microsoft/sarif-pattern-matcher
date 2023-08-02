// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/*
The `#pragma pack(push, 1)` directive ensures there is no padding between members of the struct.

I am not sure if the `alignas(1)` attribute is necessary. I want to ensure that no padding is
added to the beginning or end of the struct in any context.
*/

#pragma once
#pragma pack(push, 1)

#include <vector>

#include <cstdint>

#include "GroupNameHeader.h"
#include "Submatch.h"

struct MatchesCaptureGroupsOutput {
	GroupNameHeader* groupNameHeaders;
	uint8_t*         groupNamesBuffer;
	int              numGroupNames;
	Submatch**       matches;
	int              numMatches;
	int              numSubmatches;

	std::vector<GroupNameHeader>* groupNameHeadersCleanupPtr;
	std::vector<uint8_t>*         groupNamesBufferCleanupPtr;
	std::vector<Submatch*>*       matchesCleanupPtr;
};

#pragma pack(pop)
