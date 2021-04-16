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
std::vector<re2::RE2*> *cachedExpressions;

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
	if(timeoutMilliseconds > 0) start = std::chrono::high_resolution_clock::now();

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
extern "C" __declspec(dllexport) void GetRegexSetup(
	_In_  StringUtf8 pattern,
	_Out_ uint64_t* numCapturingGroups,
	_Out_ uint64_t* numNamedCapturingGroups,
	_Out_ uint64_t* groupNamesBufferSize)
{
	// Compile RE2 from pattern.
	re2::RE2::Options options;
	re2::StringPiece patternSp(reinterpret_cast<char*>(pattern.Bytes), pattern.Length);
	re2::RE2 re(patternSp, options);

	*numCapturingGroups = re.NumberOfCapturingGroups();
	*numNamedCapturingGroups = re.NamedCapturingGroups().size();
	
	*groupNamesBufferSize = 0;
	for (auto const& pair : re.NamedCapturingGroups())
	{
		std::string groupName = pair.first;
		(*groupNamesBufferSize) += groupName.length();
	}
}

// pattern must use RE2 syntax
extern "C" __declspec(dllexport) bool MatchesNamedGroups(
	_In_    StringUtf8 pattern,
	_In_	StringUtf8 text,
	_Inout_ GroupNameHeader* groupNameHeaders,
	_Inout_ uint8_t* groupNamesBuffer,
	_Inout_ Submatch* submatches)
{
	// Convert StringUtf8 to string piece.
	re2::StringPiece patternSp(reinterpret_cast<char*>(pattern.Bytes), pattern.Length);
	re2::StringPiece textSp(reinterpret_cast<char*>(text.Bytes), text.Length);

	// Compile RE2 regex from pattern.
	re2::RE2::Options options;
	re2::RE2 re(patternSp, options);

	// Build group names buffer.
	//- Iterate through group names and indices.
	for (auto const& pair : re.CapturingGroupNames())
	{
		//- Extract index and group name.
		int index = pair.first;
		std::string groupName = pair.second;

		//- Write group name header.
		groupNameHeaders->Index = index;
		groupNameHeaders->Length = groupName.length();
		
		//- Advance pointer to next entry.
		groupNameHeaders += 1;

		//- Write group name string.
		std::memcpy(groupNamesBuffer, groupName.data(), groupName.length());
		
		//- Advance pointer to next entry.
		groupNamesBuffer += groupName.length();
	}

	// Execute match on text using pattern.
	int numSubmatches = re.NumberOfCapturingGroups() + 1;
	std::vector<re2::StringPiece> submatchesSp(numSubmatches);
	bool isMatch = re.Match(textSp, 0, textSp.length(), re2::RE2::UNANCHORED, submatchesSp.data(), numSubmatches);

	if (isMatch)
	{
		// Build submatches buffer.
		for (auto const& submatchSp : submatchesSp)
		{
			//- Convert submatches to substrings.
			uint64_t index = submatchSp.data() - textSp.data();
			uint64_t length = submatchSp.length();

			//- Write submatch entry.
			submatches->Index = index;
			submatches->Length = length;

			//- Advance pointer to next entry.
			submatches += 1;
		}

		return true;
	}
	else
	{
		return false;
	}
}
