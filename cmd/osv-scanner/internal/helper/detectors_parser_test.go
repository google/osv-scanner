package helper

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/detector/cis/generic_linux/etcpasswdpermissions"
	"github.com/google/osv-scalibr/detector/govulncheck/binary"
	"github.com/google/osv-scalibr/detector/weakcredentials/codeserver"
	"github.com/google/osv-scalibr/detector/weakcredentials/etcshadow"
	"github.com/google/osv-scalibr/detector/weakcredentials/filebrowser"
	"github.com/google/osv-scalibr/detector/weakcredentials/winlocal"
)

func TestResolveEnabledDetectors(t *testing.T) {
	t.Parallel()

	type args struct {
		enabledDetectors  []string
		disabledDetectors []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "nothing_enabled_or_disabled",
			args: args{
				enabledDetectors:  nil,
				disabledDetectors: nil,
			},
			want: []string{},
		},
		{
			name: "empty_strings_are_ignored",
			args: args{
				enabledDetectors:  []string{""},
				disabledDetectors: []string{""},
			},
			want: []string{},
		},
		//
		{
			name: "one_detector_enabled_and_nothing_disabled",
			args: args{
				enabledDetectors:  []string{etcshadow.Name},
				disabledDetectors: nil,
			},
			want: []string{etcshadow.Name},
		},
		{
			name: "one_detector_enabled_and_different_detector_disabled",
			args: args{
				enabledDetectors:  []string{etcshadow.Name},
				disabledDetectors: []string{binary.Name},
			},
			want: []string{etcshadow.Name},
		},
		{
			name: "one_detector_enabled_and_same_detector_disabled",
			args: args{
				enabledDetectors:  []string{etcshadow.Name},
				disabledDetectors: []string{etcshadow.Name},
			},
			want: []string{},
		},
		//
		{
			name: "one_preset_enabled_and_nothing_disabled",
			args: args{
				enabledDetectors:  []string{"weakcreds"},
				disabledDetectors: nil,
			},
			want: []string{
				codeserver.Name,
				etcshadow.Name,
				filebrowser.Name,
				winlocal.Name,
			},
		},
		{
			name: "one_preset_enabled_and_different_preset_disabled",
			args: args{
				enabledDetectors:  []string{"weakcreds"},
				disabledDetectors: []string{"untested"},
			},
			want: []string{
				codeserver.Name,
				etcshadow.Name,
				filebrowser.Name,
				winlocal.Name,
			},
		},
		{
			name: "one_preset_enabled_and_same_preset_disabled",
			args: args{
				enabledDetectors:  []string{"weakcreds"},
				disabledDetectors: []string{"weakcreds"},
			},
			want: []string{},
		},
		{
			name: "one_preset_enabled_and_some_detectors_disabled",
			args: args{
				enabledDetectors:  []string{"weakcreds"},
				disabledDetectors: []string{codeserver.Name, filebrowser.Name},
			},
			want: []string{
				etcshadow.Name,
				winlocal.Name,
			},
		},
		//
		{
			name: "multiple_presets_enabled_and_nothing_disabled",
			args: args{
				enabledDetectors:  []string{"weakcreds", "cis"},
				disabledDetectors: []string{},
			},
			want: []string{
				codeserver.Name,
				etcshadow.Name,
				filebrowser.Name,
				winlocal.Name,
				etcpasswdpermissions.Name,
			},
		},
		//
		{
			name: "multiple_detectors_enabled_and_one_disabled_preset",
			args: args{
				enabledDetectors: []string{
					etcshadow.Name,
					filebrowser.Name,
					etcpasswdpermissions.Name,
				},
				disabledDetectors: []string{"weakcreds"},
			},
			want: []string{
				etcpasswdpermissions.Name,
			},
		},
		{
			name: "multiple_detectors_enabled_and_disabled",
			args: args{
				enabledDetectors: []string{
					etcshadow.Name,
					filebrowser.Name,
					etcpasswdpermissions.Name,
				},
				disabledDetectors: []string{
					codeserver.Name,
					winlocal.Name,
				},
			},
			want: []string{
				etcshadow.Name,
				filebrowser.Name,
				etcpasswdpermissions.Name,
			},
		},
		//
		{
			name: "detector_that_does_not_exist",
			args: args{
				enabledDetectors:  []string{"???"},
				disabledDetectors: nil,
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ResolveEnabledDetectors(tt.args.enabledDetectors, tt.args.disabledDetectors)

			slices.Sort(tt.want)

			gotNames := make([]string, 0, len(got))
			for _, detector := range got {
				gotNames = append(gotNames, detector.Name())
			}

			slices.Sort(gotNames)

			if diff := cmp.Diff(tt.want, gotNames); diff != "" {
				t.Errorf("replaceJSONInput() diff (-want +got): %s", diff)
			}
		})
	}
}
