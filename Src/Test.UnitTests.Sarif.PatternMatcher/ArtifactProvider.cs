﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO.Compression;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    public class ArtifactProvider : IArtifactProvider
    {
        internal ArtifactProvider(IFileSystem fileSystem)
        {
            FileSystem = fileSystem;
        }

        public ArtifactProvider(IEnumerable<IEnumeratedArtifact> artifacts)
        {
            Artifacts = new List<IEnumeratedArtifact>(artifacts);
        }

        public virtual IEnumerable<IEnumeratedArtifact> Artifacts { get; set; }

        public ICollection<IEnumeratedArtifact> Skipped { get; set; }
        public IFileSystem FileSystem { get; set; }
    }

    public class ZipArchiveArtifactProvider : ArtifactProvider
    {
        private readonly ZipArchive zipArchive;

        public ZipArchiveArtifactProvider(ZipArchive zipArchive, IFileSystem fileSystem) : base(fileSystem)
        {
            this.zipArchive = zipArchive;
        }

        public override IEnumerable<IEnumeratedArtifact> Artifacts
        {
            get
            {
                foreach (ZipArchiveEntry entry in this.zipArchive.Entries)
                {
                    yield return new EnumeratedArtifact(Sarif.FileSystem.Instance)
                    {
                        Uri = new Uri(entry.FullName, UriKind.RelativeOrAbsolute),
                        Stream = entry.Open()
                    };
                }
            }
        }
    }
}