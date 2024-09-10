package main

import (
	"reflect"
	"testing"
)

func Test_splitLastArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			args: []string{
				"--test1",
				"--test2",
				"--test3\n--test4\n--test5",
			},
			want: []string{
				"--test1",
				"--test2",
				"--test3",
				"--test4",
				"--test5",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := splitLastArg(tt.args); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitLastArg() = %v, want %v", got, tt.want)
			}
		})
	}
}
