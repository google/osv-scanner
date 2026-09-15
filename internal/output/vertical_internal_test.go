package output

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		limit int
		want  string
	}{
		{
			name:  "multibyte without whitespace",
			input: strings.Repeat("\u754c", 100),
			limit: 80,
			want:  strings.Repeat("\u754c", 80) + "...",
		},
		{
			name:  "multibyte with whitespace boundary",
			input: strings.Repeat("\u754c", 30) + " " + strings.Repeat("\u8a9e", 60),
			limit: 80,
			want:  strings.Repeat("\u754c", 30) + "...",
		},
		{
			name:  "ASCII without whitespace",
			input: strings.Repeat("a", 100),
			limit: 80,
			want:  strings.Repeat("a", 80) + "...",
		},
		{
			name:  "short string unchanged",
			input: "short text",
			limit: 80,
			want:  "short text",
		},
		{
			name:  "zero limit preserves existing behavior",
			input: "text",
			limit: 0,
			want:  "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := truncate(tt.input, tt.limit)
			if got != tt.want {
				t.Fatalf("truncate() = %q, want %q", got, tt.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("truncate() returned invalid UTF-8: %q", got)
			}
		})
	}
}
