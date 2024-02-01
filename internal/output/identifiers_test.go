package output

import (
	"slices"
	"testing"
)

func Test_idSortFunc(t *testing.T) {
	t.Parallel()

	type args struct {
		a string
		b string
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			args: args{
				a: "CVE-2012-1234",
				b: "ANYTHING-2012-1234",
			},
			want: -1,
		},
		{
			args: args{
				a: "GHSA-2012-1234",
				b: "ANYTHING-2012-1234",
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := idSortFunc(tt.args.a, tt.args.b); got != tt.want {
				t.Errorf("idSortFunc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_idSortFuncUsage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			args: []string{
				"CVE-2012-1234",
				"ANYTHING-2012-1234",
			},
			want: "CVE-2012-1234",
		},
		{
			args: []string{
				"GHSA-2012-1234",
				"RUSTSEC-2012-1234",
			},
			want: "RUSTSEC-2012-1234",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := slices.MinFunc(tt.args, idSortFunc); got != tt.want {
				t.Errorf("slices.MinFunc = %v, want %v", got, tt.want)
			}
		})
	}
}
