package vendored

import (
	//nolint:gosec //md5 used to identify files, not for security purposes
	"crypto/md5"
	"testing"
)

// TestNormalizeLineEndingsForHash covers issue #657: on Windows, Git's core.autocrlf
// setting rewrites CRLF ("\r\n") into vendored C/C++ source files on checkout. Because
// queryDetermineVersions hashes the raw file bytes, the resulting MD5 hash differs from
// the hash of the same logical source checked out with LF-only line endings on Linux/macOS,
// so the determine-version API lookup silently fails to match and known-vulnerable
// vendored libraries go undetected on Windows.
func TestNormalizeLineEndingsForHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		crlf []byte
		lf   []byte
	}{
		{
			name: "simple_multiline_source",
			crlf: []byte("#include <stdio.h>\r\n\r\nint main() {\r\n    return 0;\r\n}\r\n"),
			lf:   []byte("#include <stdio.h>\n\nint main() {\n    return 0;\n}\n"),
		},
		{
			name: "no_trailing_newline",
			crlf: []byte("int x = 1;\r\nint y = 2;"),
			lf:   []byte("int x = 1;\nint y = 2;"),
		},
		{
			name: "already_lf_only_is_unchanged",
			crlf: []byte("already\nlf\nonly\n"),
			lf:   []byte("already\nlf\nonly\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotFromCRLF := normalizeLineEndingsForHash(tt.crlf)
			gotFromLF := normalizeLineEndingsForHash(tt.lf)

			if string(gotFromCRLF) != string(gotFromLF) {
				t.Errorf("normalizeLineEndingsForHash gave different results for CRLF vs LF checkouts of the same source:\nfrom CRLF: %q\nfrom LF:   %q", gotFromCRLF, gotFromLF)
			}

			gotHash := md5.Sum(normalizeLineEndingsForHash(tt.crlf)) //nolint:gosec //md5 used to identify files, not for security purposes
			wantHash := md5.Sum(normalizeLineEndingsForHash(tt.lf))  //nolint:gosec //md5 used to identify files, not for security purposes
			if gotHash != wantHash {
				t.Errorf("hash mismatch between CRLF and LF checkouts of the same source: %x != %x", gotHash, wantHash)
			}
		})
	}

	t.Run("lone_CR_not_part_of_CRLF_is_preserved", func(t *testing.T) {
		t.Parallel()

		in := []byte("a\rb\r\nc")
		want := []byte("a\rb\nc")
		got := normalizeLineEndingsForHash(in)
		if string(got) != string(want) {
			t.Errorf("normalizeLineEndingsForHash(%q) = %q, want %q", in, got, want)
		}
	})
}
