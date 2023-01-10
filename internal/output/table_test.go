package output

import "testing"

func Test_wrapPath(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "No wrap",
			args: args{
				path: "some/short/path",
			},
			want: "some/short/path",
		},
		{
			name: "Wrapping",
			args: args{
				path: "a/much/much/longer/path/here12345678901234567",
			},
			want: "a/much/much/longer/path/\nhere12345678901234567",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wrapPath(tt.args.path); got != tt.want {
				t.Errorf("wrapPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
