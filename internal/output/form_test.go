package output_test

import (
	"testing"

	"github.com/google/osv-scanner/internal/output"
)

func TestForm(t *testing.T) {
	t.Parallel()

	type args struct {
		count    int
		singular string
		plural   string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "",
			args: args{
				count:    0,
				singular: "package",
				plural:   "packages",
			},
			want: "packages",
		},
		{
			name: "",
			args: args{
				count:    1,
				singular: "package",
				plural:   "packages",
			},
			want: "package",
		},
		{
			name: "",
			args: args{
				count:    2,
				singular: "package",
				plural:   "packages",
			},
			want: "packages",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := output.Form(tt.args.count, tt.args.singular, tt.args.plural); got != tt.want {
				t.Errorf("Form() = %v, want %v", got, tt.want)
			}
		})
	}
}
