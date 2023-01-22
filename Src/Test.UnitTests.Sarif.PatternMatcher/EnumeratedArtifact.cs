// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.IO;
using System.Text;

namespace Microsoft.CodeAnalysis.Sarif.PatternMatcher
{
    internal class EnumeratedArtifact : IEnumeratedArtifact
    {
        private string contents;

        public Uri Uri { get; set; }
        
        public Stream Stream { get; set; }
        
        public Encoding Encoding { get; set; }
        
        public string Contents
        {
            get => GetContents();
            set => this.contents = value;
        }

        private string GetContents()
        {
            if (Stream == null && this.contents == null) { return null; }
            if (this.contents != null ) {  return this.contents; }
            if (Stream.CanSeek) {  this.Stream.Seek(0, SeekOrigin.Begin);}
            using var contentReader = new StreamReader(Stream);
            this.contents = contentReader.ReadToEnd();
            Stream = null;
            return this.contents;
        }

        public ulong Size { get; set;  }
    }
}
