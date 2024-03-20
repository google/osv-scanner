// Copyright (c) 2013 Blake Smith <blakesmith0@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Modified under Apache License

package ar

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
)

const (
	HeaderByteSize = 60
	ArSignature    = "!<arch>\n"
)

type Header struct {
	Name string
	Size int
}

type slicer []byte

func (sp *slicer) next(n int) []byte {
	s := *sp

	b := s[0:n]
	*sp = s[n:]

	return b
}

// Provides read access to an ar archive.
// Call next to skip files
//
// Example:
//	reader := NewReader(f)
//	var buf bytes.Buffer
//	for {
//		_, err := reader.Next()
//		if err == io.EOF {
//			break
//		}
//		if err != nil {
//			t.Errorf(err.Error())
//		}
//		io.Copy(&buf, reader)
//	}

type Reader struct {
	r           io.Reader
	bytesToRead int
	pad         int
}

// Copies read data to r. Strips the global ar header.
func NewReader(r io.Reader) (*Reader, error) {
	sigBuf := bytes.Buffer{}
	_, _ = io.CopyN(&sigBuf, r, 8) // Discard global header

	if sigBuf.String() != ArSignature {
		return nil, errors.New("not an rlib archive")
	}

	return &Reader{r: r}, nil
}

// Call Next() to skip to the next file in the archive file.
// Returns a Header which contains the metadata about the
// file in the archive.
func (rd *Reader) Next() (*Header, error) {
	err := rd.skipUnread()
	if err != nil {
		return nil, err
	}

	return rd.readHeader()
}

// Read data from the current entry in the archive.
func (rd *Reader) Read(b []byte) (n int, err error) {
	if rd.bytesToRead == 0 {
		return 0, io.EOF
	}
	if len(b) > rd.bytesToRead {
		b = b[0:rd.bytesToRead]
	}
	n, err = rd.r.Read(b)
	rd.bytesToRead -= n

	return
}

func (rd *Reader) skipUnread() error {
	bytesToSkip := int64(rd.bytesToRead + rd.pad)
	rd.bytesToRead, rd.pad = 0, 0
	if seeker, ok := rd.r.(io.Seeker); ok {
		_, err := seeker.Seek(bytesToSkip, io.SeekCurrent)
		return err
	} else {
		_, err := io.CopyN(io.Discard, rd.r, bytesToSkip)
		return err
	}
}

func (rd *Reader) readHeader() (*Header, error) {
	headerBuf := make([]byte, HeaderByteSize)
	if _, err := io.ReadFull(rd.r, headerBuf); err != nil {
		return nil, err
	}

	header := new(Header)
	s := slicer(headerBuf)

	header.Name = byteToString(s.next(16))
	// Skip the next 4 fields, we only need name and size
	s.next(12 + 6 + 6 + 8)
	header.Size = byteToDecimal(s.next(10))

	rd.bytesToRead = header.Size
	rd.pad = header.Size % 2

	return header, nil
}

func byteToString(b []byte) string {
	return strings.TrimRight(string(b), " ")
}

func byteToDecimal(b []byte) int {
	n, _ := strconv.Atoi(byteToString(b))
	return n
}
