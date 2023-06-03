// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Newtonsoft.Json;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class JsonLogicalLocationProcessor
    {
        /// <summary>
        ///  This processor finds the JSON path for the file matches.
        ///   If a match is between tokens or spans tokens, it returns the path of the
        ///   last token which starts before the match start.
        /// </summary>
        /// <remarks>
        ///  Observations:
        ///   - All JSON tokens are on one line, because JSON requires newline escaping.
        ///     - Therefore, the token containing the start position must start on the start position line.
        ///   - Matches which span tokens will use the path of the last token starting before the match start.
        ///     - For name:value, both have the same path.
        ///     - For arrays, one might report the whole array, but this gets "closer" to the match.
        ///     - For objects, spanning properties will get "closer" to the match.
        /// </remarks>
        /// <param name="results">A collection of 'Result' objects produced by an analysis tool where each object contains many details such as RuleId, Kind, Level, Locations, etc.</param>
        /// <param name="fileContents">This is the litteral JSON file contents.</param>
        /// <param name="fileRegionsCache">This file cache can be used to populate regions with comprehensive data.</param>
        public void Process(ICollection<Result> results, string fileContents, FileRegionsCache fileRegionsCache = null)
        {
            if (results?.Count == 0) { return; }

            // Parse the JSON to determine the JSON paths of each match
            // NOTE: Matches must be sorted by file position.
            try
            {
                using (var reader = new JsonTextReader(new StringReader(fileContents)))
                {
                    string lastPath = null;

                    fileRegionsCache ??= new FileRegionsCache();

                    var sortedByLocation = new SortedDictionary<int, Result>();

                    foreach (Result result in results)
                    {
                        Location location = result.Locations[0];
                        Region region = location.PhysicalLocation.Region;

                        fileRegionsCache.PopulateTextRegionProperties(region,
                                                                      location.PhysicalLocation.ArtifactLocation.Uri,
                                                                      populateSnippet: false,
                                                                      fileText: fileContents);

                        sortedByLocation[region.CharOffset] = result;
                    }

                    foreach (Result result in sortedByLocation.Values)
                    {
                        Region region = result.Locations[0].PhysicalLocation.Region;
                        if (CurrentTokenIsAfter(reader, region))
                        {
                            // If we've already read past the match start, this must be the same path as the previous match
                            result.Locations[0].LogicalLocation = new LogicalLocation
                            {
                                FullyQualifiedName = lastPath,
                            };
                        }
                        else if (PathToLastTokenBefore(reader, region, out string path))
                        {
                            // Read to the first token after the match and store the path to the previous token
                            // If we've already read past the match start, this must be the same path as the previous match
                            result.Locations[0].LogicalLocation = new LogicalLocation
                            {
                                FullyQualifiedName = path,
                            };

                            lastPath = path;
                        }
                    }
                }
            }
            catch (JsonReaderException)
            {
                // If the JSON couldn't be parsed, do not try to find (further) logical locations.
            }
        }

        private bool PathToLastTokenBefore(JsonTextReader reader, Region region, out string path)
        {
            path = null;

            // Read to the line number of the match (or end of file)
            while (reader.LineNumber < region.StartLine)
            {
                if (!reader.Read()) { return false; }
            }

            // Read until the first token which ends after the match start
            // [JsonTextReader LinePosition is for the last character in the token]
            while (reader.LineNumber == region.StartLine && reader.LinePosition < region.StartColumn)
            {
                if (!reader.Read()) { return false; }
            }

            path = reader.Path;
            return true;
        }

        private bool CurrentTokenIsAfter(JsonTextReader reader, Region region)
        {
            return
                reader.LineNumber > region.StartLine ||
                (reader.LineNumber == region.StartLine && reader.LinePosition > region.StartColumn);
        }

        /// <summary>
        ///  ToFingerprint converts the JSON path logical location to a canonical
        ///  form safe to use as a stable fingerprint. It removes all array indices
        ///  from the path to cause results to match when they move within arrays.
        /// </summary>
        /// <param name="logicalLocation">JsonPath logical location to convert.</param>
        /// <returns>Canonical Logical Location safe for fingerprint use, or null if unable to compute.</returns>
        public static string ToFingerprint(string logicalLocation)
        {
            if (string.IsNullOrEmpty(logicalLocation)) { return null; }

            var fingerprint = new StringBuilder();

            // Copy the JSON path with all array indices removed ([15] => [])
            int copiedFromIndex = 0;
            while (true)
            {
                // Find the next brace
                int brace = logicalLocation.IndexOf('[', copiedFromIndex);
                if (brace == -1) { break; }

                // Copy everything up to and including the brace
                fingerprint.Append(logicalLocation, copiedFromIndex, brace + 1 - copiedFromIndex);

                // Find the closing brace
                copiedFromIndex = logicalLocation.IndexOf(']', brace + 1);

                // If there is no matching brace, return null (can't compute)
                if (copiedFromIndex == -1) { return null; }
            }

            // Copy the rest of the Json path
            if (copiedFromIndex < logicalLocation.Length)
            {
                fingerprint.Append(logicalLocation, copiedFromIndex, logicalLocation.Length - copiedFromIndex);
            }

            return fingerprint.ToString();
        }
    }
}
