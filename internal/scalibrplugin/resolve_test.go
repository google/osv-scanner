package scalibrplugin_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	apkanno "github.com/google/osv-scalibr/annotator/osduplicate/apk"
	dpkganno "github.com/google/osv-scalibr/annotator/osduplicate/dpkg"
	"github.com/google/osv-scalibr/detector/cis/generic_linux/etcpasswdpermissions"
	"github.com/google/osv-scalibr/detector/govulncheck/binary"
	"github.com/google/osv-scalibr/detector/weakcredentials/codeserver"
	"github.com/google/osv-scalibr/detector/weakcredentials/etcshadow"
	"github.com/google/osv-scalibr/detector/weakcredentials/filebrowser"
	"github.com/google/osv-scalibr/detector/weakcredentials/winlocal"
	"github.com/google/osv-scalibr/enricher/baseimage"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"
	chromeextensions "github.com/google/osv-scalibr/extractor/filesystem/misc/chrome/extensions"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/filesystem/vendored"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/vcs/gitrepo"
	"github.com/google/osv-scanner/v2/internal/scalibrplugin"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestResolve(t *testing.T) {
	t.Parallel()

	type args struct {
		enabled  []string
		disabled []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "nothing_enabled_or_disabled",
			args: args{
				enabled:  nil,
				disabled: nil,
			},
			want: []string{},
		},
		{
			name: "empty_strings_are_ignored",
			args: args{
				enabled:  []string{""},
				disabled: []string{""},
			},
			want: []string{},
		},
		//
		{
			name: "one_extractor_and_one_detector_enabled_and_nothing_disabled",
			args: args{
				enabled:  []string{composerlock.Name, etcshadow.Name},
				disabled: nil,
			},
			want: []string{composerlock.Name, etcshadow.Name},
		},
		{
			name: "one_extractor_and_one_detector_enabled_and_different_detector_disabled",
			args: args{
				enabled:  []string{composerlock.Name, etcshadow.Name},
				disabled: []string{binary.Name},
			},
			want: []string{composerlock.Name, etcshadow.Name},
		},
		{
			name: "one_extractor_and_one_detector_enabled_and_different_extractor_disabled",
			args: args{
				enabled:  []string{composerlock.Name, etcshadow.Name},
				disabled: []string{binary.Name, chromeextensions.Name},
			},
			want: []string{composerlock.Name, etcshadow.Name},
		},
		{
			name: "one_extractor_enabled_and_one_detector_enabled_and_same_detector_disabled",
			args: args{
				enabled:  []string{composerlock.Name, etcshadow.Name},
				disabled: []string{etcshadow.Name},
			},
			want: []string{composerlock.Name},
		},
		{
			name: "one_extractor_enabled_and_one_detector_enabled_and_same_extractor_disabled",
			args: args{
				enabled:  []string{composerlock.Name, etcshadow.Name},
				disabled: []string{composerlock.Name},
			},
			want: []string{etcshadow.Name},
		},
		//
		{
			name: "some_extractors_and_one_detector_preset_enabled_and_nothing_disabled",
			args: args{
				enabled:  []string{composerlock.Name, "weakcreds", nodemodules.Name},
				disabled: nil,
			},
			want: []string{
				codeserver.Name,
				composerlock.Name,
				etcshadow.Name,
				filebrowser.Name,
				nodemodules.Name,
				winlocal.Name,
			},
		},
		{
			name: "one_preset_enabled_and_different_preset_disabled",
			args: args{
				enabled:  []string{"weakcreds"},
				disabled: []string{"artifact"},
			},
			want: []string{
				codeserver.Name,
				etcshadow.Name,
				filebrowser.Name,
				winlocal.Name,
			},
		},
		//
		{
			name: "multiple_presets_enabled_and_nothing_disabled",
			args: args{
				enabled:  []string{"weakcreds", "sbom"},
				disabled: []string{},
			},
			want: []string{
				cdx.Name,
				codeserver.Name,
				etcshadow.Name,
				filebrowser.Name,
				spdx.Name,
				winlocal.Name,
			},
		},
		//
		{
			name: "plugin_that_does_not_exist",
			args: args{
				enabled:  []string{"???"},
				disabled: nil,
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := scalibrplugin.Resolve(tt.args.enabled, tt.args.disabled)

			slices.Sort(tt.want)

			gotNames := make([]string, 0, len(got))
			for _, plug := range got {
				gotNames = append(gotNames, plug.Name())
			}

			slices.Sort(gotNames)

			if diff := cmp.Diff(tt.want, gotNames); diff != "" {
				t.Errorf("Resolve() diff (-want +got): %s", diff)
			}
		})
	}
}

func TestResolve_Detectors(t *testing.T) {
	t.Parallel()

	type args struct {
		enabled  []string
		disabled []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "nothing_enabled_or_disabled",
			args: args{
				enabled:  nil,
				disabled: nil,
			},
			want: []string{},
		},
		{
			name: "empty_strings_are_ignored",
			args: args{
				enabled:  []string{""},
				disabled: []string{""},
			},
			want: []string{},
		},
		{
			name: "one_detector_enabled_and_nothing_disabled",
			args: args{
				enabled:  []string{etcshadow.Name},
				disabled: nil,
			},
			want: []string{etcshadow.Name},
		},
		{
			name: "one_detector_enabled_and_different_detector_disabled",
			args: args{
				enabled:  []string{etcshadow.Name},
				disabled: []string{binary.Name},
			},
			want: []string{etcshadow.Name},
		},
		{
			name: "one_detector_enabled_and_same_detector_disabled",
			args: args{
				enabled:  []string{etcshadow.Name},
				disabled: []string{etcshadow.Name},
			},
			want: []string{},
		},
		//
		{
			name: "one_preset_enabled_and_nothing_disabled",
			args: args{
				enabled:  []string{"weakcreds"},
				disabled: nil,
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
				enabled:  []string{"weakcreds"},
				disabled: []string{"untested"},
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
				enabled:  []string{"weakcreds"},
				disabled: []string{"weakcreds"},
			},
			want: []string{},
		},
		{
			name: "one_preset_enabled_and_some_detectors_disabled",
			args: args{
				enabled:  []string{"weakcreds"},
				disabled: []string{codeserver.Name, filebrowser.Name},
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
				enabled:  []string{"weakcreds", "cis"},
				disabled: []string{},
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
				enabled: []string{
					etcshadow.Name,
					filebrowser.Name,
					etcpasswdpermissions.Name,
				},
				disabled: []string{"weakcreds"},
			},
			want: []string{
				etcpasswdpermissions.Name,
			},
		},
		{
			name: "multiple_detectors_enabled_and_disabled",
			args: args{
				enabled: []string{
					etcshadow.Name,
					filebrowser.Name,
					etcpasswdpermissions.Name,
				},
				disabled: []string{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := scalibrplugin.Resolve(tt.args.enabled, tt.args.disabled)

			slices.Sort(tt.want)

			gotNames := make([]string, 0, len(got))
			for _, plug := range got {
				gotNames = append(gotNames, plug.Name())
			}

			slices.Sort(gotNames)

			if diff := cmp.Diff(tt.want, gotNames); diff != "" {
				t.Errorf("Resolve() diff (-want +got): %s", diff)
			}
		})
	}
}

func TestResolve_Extractors(t *testing.T) {
	t.Parallel()

	type args struct {
		enabled  []string
		disabled []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		//
		{
			name: "one_extractor_enabled_and_nothing_disabled",
			args: args{
				enabled:  []string{composerlock.Name},
				disabled: nil,
			},
			want: []string{composerlock.Name},
		},
		{
			name: "one_extractor_enabled_and_different_extractor_disabled",
			args: args{
				enabled:  []string{composerlock.Name},
				disabled: []string{packageslockjson.Name},
			},
			want: []string{composerlock.Name},
		},
		{
			name: "one_extractor_enabled_and_same_extractor_disabled",
			args: args{
				enabled:  []string{composerlock.Name},
				disabled: []string{composerlock.Name},
			},
			want: []string{},
		},
		//
		{
			name: "one_preset_enabled_and_nothing_disabled",
			args: args{
				enabled:  []string{"artifact"},
				disabled: nil,
			},
			want: []string{
				apk.Name,
				archive.Name,
				baseimage.Name,
				cargoauditable.Name,
				dpkg.Name,
				gobinary.Name,
				nodemodules.Name,
				wheelegg.Name,
				apkanno.Name,
				dpkganno.Name,
			},
		},
		{
			name: "one_preset_enabled_and_different_preset_disabled",
			args: args{
				enabled:  []string{"artifact"},
				disabled: []string{"directory"},
			},
			want: []string{
				apk.Name,
				archive.Name,
				baseimage.Name,
				cargoauditable.Name,
				dpkg.Name,
				gobinary.Name,
				nodemodules.Name,
				wheelegg.Name,
				apkanno.Name,
				dpkganno.Name,
			},
		},
		{
			name: "one_preset_enabled_and_same_preset_disabled",
			args: args{
				enabled:  []string{"artifact"},
				disabled: []string{"artifact"},
			},
			want: []string{},
		},
		{
			name: "one_preset_enabled_and_some_extractors_disabled",
			args: args{
				enabled:  []string{"artifact"},
				disabled: []string{wheelegg.Name, archive.Name, cargoauditable.Name},
			},
			want: []string{
				apk.Name,
				baseimage.Name,
				dpkg.Name,
				gobinary.Name,
				nodemodules.Name,
				apkanno.Name,
				dpkganno.Name,
			},
		},
		//
		{
			name: "multiple_presets_enabled_and_nothing_disabled",
			args: args{
				enabled:  []string{"artifact", "directory"},
				disabled: []string{},
			},
			want: []string{
				apk.Name,
				archive.Name,
				baseimage.Name,
				cargoauditable.Name,
				dpkg.Name,
				gitrepo.Name,
				gobinary.Name,
				nodemodules.Name,
				vendored.Name,
				wheelegg.Name,
				apkanno.Name,
				dpkganno.Name,
			},
		},
		//
		{
			name: "multiple_extractors_enabled_and_one_disabled_preset",
			args: args{
				enabled: []string{
					spdx.Name,
					archive.Name,
					gobinary.Name,
				},
				disabled: []string{"sbom"},
			},
			want: []string{
				archive.Name,
				gobinary.Name,
			},
		},
		{
			name: "multiple_extractors_enabled_and_disabled",
			args: args{
				enabled: []string{
					spdx.Name,
					archive.Name,
					gobinary.Name,
					cargoauditable.Name,
				},
				disabled: []string{
					cdx.Name,
					wheelegg.Name,
					gobinary.Name,
					apk.Name,
					apkanno.Name,
					dpkganno.Name,
				},
			},
			want: []string{
				spdx.Name,
				archive.Name,
				cargoauditable.Name,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := scalibrplugin.Resolve(tt.args.enabled, tt.args.disabled)

			slices.Sort(tt.want)

			gotNames := make([]string, 0, len(got))
			for _, plug := range got {
				gotNames = append(gotNames, plug.Name())
			}

			slices.Sort(gotNames)

			if diff := cmp.Diff(tt.want, gotNames); diff != "" {
				t.Errorf("Resolve() diff (-want +got): %s", diff)
			}
		})
	}
}

func TestResolve_Detectors_Presets(t *testing.T) {
	t.Parallel()

	for _, preset := range []string{"cis", "govulncheck", "untested", "weakcreds"} {
		t.Run(preset, func(t *testing.T) {
			t.Parallel()

			got := scalibrplugin.Resolve([]string{preset}, []string{})

			gotNames := make([]string, 0, len(got))
			for _, detector := range got {
				gotNames = append(gotNames, detector.Name())
			}

			slices.Sort(gotNames)

			testutility.NewSnapshot().MatchText(t, strings.Join(gotNames, "\n"))
		})
	}
}

func TestResolve_Extractors_Presets(t *testing.T) {
	t.Parallel()

	for _, preset := range []string{"sbom", "lockfile", "directory", "artifact"} {
		t.Run(preset, func(t *testing.T) {
			t.Parallel()

			got := scalibrplugin.Resolve([]string{preset}, []string{})

			gotNames := make([]string, 0, len(got))
			for _, extractor := range got {
				gotNames = append(gotNames, extractor.Name())
			}

			slices.Sort(gotNames)

			testutility.NewSnapshot().MatchText(t, strings.Join(gotNames, "\n"))
		})
	}
}
