// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "stdafx.h"
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <cstdint>
#include "re2.h"
#include "Match2.h"
#include "String8.h"

#include "GroupNameHeader.h"
#include "Submatch.h"
#include "StringUtf8.h"
#include "MatchesCaptureGroupsOutput.h"

// System.Text.RegularExpressions.RegexOptions
const int RegexOptions_IgnoreCase = 0x1;
const int RegexOptions_Multiline = 0x2;
const int RegexOptions_ExplicitCapture = 0x4;
const int RegexOptions_Compiled = 0x8;
const int RegexOptions_Singleline = 0x10;
const int RegexOptions_IgnorePatternWhitespace = 0x20;
const int RegexOptions_RightToLeft = 0x40;
const int RegexOptions_Debug = 0x80;
const int RegexOptions_ECMAScript = 0x100;
const int RegexOptions_CultureInvariant = 0x200;

// Set of RegexOptions which don't have RE2 equivalents. This excludes:
//  - RegexOptions.Compiled doesn't matter; this implementation essentially always compiles them.
//  - RegexOptions.ExplicitCapture doesn't matter because no overloads which return the captures are offered.
//  - RegexOptions.CultureInvariant doesn't matter; RE2 doesn't support culture sensitive behavior.
const int RegexOptions_ThrowOnMask = RegexOptions_Multiline | RegexOptions_IgnorePatternWhitespace | RegexOptions_RightToLeft | RegexOptions_ECMAScript;

extern "C" __declspec(dllexport) int Test()
{
	// Attempt Sample RE2 usage via P/Invoke from C#
	re2::RE2 re("(\\w+):(\\d+)");
	if (re2::RE2::PartialMatch("test:1234", re)) return 1;

	return 0;
}

std::mutex cachedExpressionsMutex;

// Maintain a static vector to cache parsed RE2 regular expressions
// RE2 instances are safe for concurrent use across threads.
std::vector<re2::RE2*>* cachedExpressions;

// Parse and Cache a Regular Expression for later runs
extern "C" __declspec(dllexport) int BuildRegex(String8 regex, int regexOptions)
{
	std::lock_guard<std::mutex> lock(cachedExpressionsMutex);

	// Allocate the vector if this is the first call
	if (cachedExpressions == nullptr) cachedExpressions = new std::vector<re2::RE2*>();

	// Return error if Regex options contains flags not supported by RE2
	if ((regexOptions & RegexOptions_ThrowOnMask) != 0) return -2;

	// Convert expression String8 to RE2 StringPiece
	if (regex.Index < 0 || regex.Length < 0 || regex.Array + regex.Index + regex.Length < regex.Array) return -1;
	re2::StringPiece expressionSp(regex.Array + regex.Index, regex.Length);

	// Convert options to RE2 equivalent
	re2::RE2::Options* options = new re2::RE2::Options();
	if ((regexOptions & RegexOptions_IgnoreCase) != 0) options->set_case_sensitive(false);
	if ((regexOptions & RegexOptions_Singleline) != 0) options->set_dot_nl(true);

	// Parse and construct an RE2 instance for the regular expression
	re2::RE2* expression = new re2::RE2(expressionSp, *options);

	// If the expression didn't parse, return an error
	// Not returning the native allocated error message; it's visible in stdout.
	if (expression->error_code() != 0)
	{
		delete expression;
		return -1;
	}

	// Add the expression to the vector and return the index of it
	cachedExpressions->push_back(expression);
	return (int)(cachedExpressions->size() - 1);
}

// Release all cached Regular Expressions
extern "C" __declspec(dllexport) void ClearRegexes()
{
	// Release all cached expressions and the vector itself
	if (cachedExpressions != nullptr)
	{
		for (int i = 0; i < (int)cachedExpressions->size(); ++i)
		{
			delete cachedExpressions->at(i);
		}

		delete cachedExpressions;
		cachedExpressions = nullptr;
	}
}

extern "C" int GetCachedExpression(int regexIndex, re2::RE2** ppRE2)
{
	std::lock_guard<std::mutex> lock(cachedExpressionsMutex);
	if (regexIndex < 0 || regexIndex >= (int)cachedExpressions->size()) return -(int)cachedExpressions->size();
	*ppRE2 = cachedExpressions->at(regexIndex);
	return regexIndex;
}

// Find matches for a cached regular expression in UTF8 text and fill the matches array with them.
// Return the count of matches found or -1 for errors.
extern "C" __declspec(dllexport) int Matches(int regexIndex, String8 text, int fromTextIndex, Match2* matches, int matchesLength, int timeoutMilliseconds)
{
	re2::RE2* re;
	int index = GetCachedExpression(regexIndex, &re);
	if (index < 0) { return index; }

	// Wrap the UTF-8 text in RE2's string span wrapper
	if (text.Index < 0 || text.Length < 0 || text.Array + text.Index + text.Length < text.Array) return -1;
	re2::StringPiece allContentSp(text.Array + text.Index, text.Length);

	// Get the time to measure the timeout
	std::chrono::high_resolution_clock::time_point start;
	if (timeoutMilliseconds > 0) start = std::chrono::high_resolution_clock::now();

	// Find matches until the matches array is full or we run out of text
	re2::StringPiece captures[1];
	int nextMatchIndex = 0;
	while (nextMatchIndex < matchesLength)
	{
		// Find the next match, capturing only the overall match span
		if (!re->Match(allContentSp, fromTextIndex, allContentSp.length(), re2::RE2::UNANCHORED, captures, 1)) break;

		// Identify the match UTF-8 byte offset and length
		int matchOffset = (int)(captures[0].data() - allContentSp.data());
		matches[nextMatchIndex].Index = matchOffset;
		matches[nextMatchIndex].Length = (int)(captures[0].length());
		nextMatchIndex++;

		// Continue search on the character after the match start
		fromTextIndex = matchOffset + 1;

		if (timeoutMilliseconds > 0)
		{
			std::chrono::high_resolution_clock::time_point now = std::chrono::high_resolution_clock::now();
			if (std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count() > timeoutMilliseconds) break;
		}
	}

	// Return the number of matches found
	return nextMatchIndex;
}

// pattern must use RE2 syntax
//
// Implementation note: The data std::vector is guaranteed to be contiguous by the C++ standard,
// so we can pass it to C# space for pointer-based copying.
extern "C" __declspec(dllexport) void MatchesCaptureGroups(
	_In_  int regexIndex,
	_In_  String8 text,
	_Out_ MatchesCaptureGroupsOutput** outputOut
)
{
	re2::RE2* re;
	int index = GetCachedExpression(regexIndex, &re);
	if (index < 0) { return; }

	// Wrap the UTF-8 text in RE2's string span wrapper
	if (text.Index < 0 || text.Length < 0 || text.Array + text.Index + text.Length < text.Array) return;
	re2::StringPiece allContentSp(text.Array + text.Index, text.Length);

	// Compute the number of submatches in the pattern.
	int numSubmatches = re->NumberOfCapturingGroups() + 1;

	// Build group name headers and buffer.
	std::vector<GroupNameHeader>* groupNameHeaderVectorPtr = new std::vector<GroupNameHeader>();
	std::vector<uint8_t>* groupNameBufferVectorPtr = new std::vector<uint8_t>();
	for (auto const& pair : re->CapturingGroupNames())
	{
		// Extract index and group name.
		int index = pair.first;
		std::string groupName = pair.second;

		// Add group name header.
		GroupNameHeader groupNameHeader;
		groupNameHeader.Index = index;
		groupNameHeader.Length = static_cast<int32_t>(groupName.length());
		groupNameHeaderVectorPtr->push_back(groupNameHeader);

		// Add group name string.
		for (size_t i = 0; i < groupName.length(); i++)
		{
			groupNameBufferVectorPtr->push_back(groupName.data()[i]);
		}
	}

	// Create an array to hold the submatches of each match.
	std::vector<re2::StringPiece> submatchesSp(numSubmatches);

	// Allocate a vector to hold the matches.
	std::vector<Submatch*>* matchesVectorPtr = new std::vector<Submatch*>();

	// Extract successive non-overlapping matches from the text.
	re2::StringPiece::size_type startpos = 0;
	while (true)
	{
		// Stop searching if we have run out of text.
		if (startpos >= allContentSp.length())
		{
			break;
		}

		// Extract next match from text using pattern.
		bool isMatch = re->Match(allContentSp, startpos, allContentSp.length(), re2::RE2::UNANCHORED, submatchesSp.data(), numSubmatches);

		// Stop searching if no more matches are found.
		if (!isMatch)
		{
			break;
		}

		// Allocate an array to record submatches for this match.
		Submatch* submatches = new Submatch[numSubmatches];
		matchesVectorPtr->push_back(submatches);

		// Write submatches.
		for (auto const& submatchSp : submatchesSp)
		{
			if (submatchSp.data() == 0)
			{
				// This is an optional group that was not found.
				submatches->Index = -1;
				submatches->Length = -1;
			}
			else
			{
				// This group was found.

				// Convert submatches to substring index and length.
				int32_t index = static_cast<int32_t>(submatchSp.data() - allContentSp.data());
				int32_t length = static_cast<int32_t>(submatchSp.length());

				// Write submatch entry.
				submatches->Index = index;
				submatches->Length = length;
			}

			// Advance pointer to next entry.
			submatches += 1;
		}

		// Advance the starting position past this match.
		re2::StringPiece fullMatchSp = submatchesSp[0];
		int matchStartIndex = static_cast<int>(fullMatchSp.data() - allContentSp.data());
		startpos = matchStartIndex + fullMatchSp.length();
	}

	// Assign outputs.
	MatchesCaptureGroupsOutput* output = new MatchesCaptureGroupsOutput;
	output->groupNameHeaders = groupNameHeaderVectorPtr->data();
	output->groupNamesBuffer = groupNameBufferVectorPtr->data();
	output->numGroupNames = static_cast<int>(re->CapturingGroupNames().size());
	output->matches = matchesVectorPtr->data();
	output->numMatches = static_cast<int>(matchesVectorPtr->size());
	output->numSubmatches = numSubmatches;
	output->groupNameHeadersCleanupPtr = groupNameHeaderVectorPtr;
	output->groupNamesBufferCleanupPtr = groupNameBufferVectorPtr;
	output->matchesCleanupPtr = matchesVectorPtr;
	*outputOut = output;
}

extern "C" __declspec(dllexport) void MatchesCaptureGroupsDispose(
	_In_  MatchesCaptureGroupsOutput* output
)
{
	delete output->groupNameHeadersCleanupPtr;
	delete output->groupNamesBufferCleanupPtr;
	for (auto const& submatches : *(output->matchesCleanupPtr))
	{
		delete submatches;
	}
	delete output->matchesCleanupPtr;
	delete output;
}
