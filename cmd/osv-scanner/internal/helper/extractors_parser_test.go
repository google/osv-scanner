package helper

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scanner/v2/internal/scalibrextract/language/javascript/nodemodules"
)

func TestResolveEnabledExtractors(t *testing.T) {
	t.Parallel()

	type args struct {
		enabledExtractors  []string
		disabledExtractors []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "nothing_enabled_or_disabled",
			args: args{
				enabledExtractors:  nil,
				disabledExtractors: nil,
			},
			want: []string{},
		},
		{
			name: "empty_strings_are_ignored",
			args: args{
				enabledExtractors:  []string{""},
				disabledExtractors: []string{""},
			},
			want: []string{},
		},
		//
		{
			name: "one_extractor_enabled_and_nothing_disabled",
			args: args{
				enabledExtractors:  []string{composerlock.Name},
				disabledExtractors: nil,
			},
			want: []string{composerlock.Name},
		},
		{
			name: "one_extractor_enabled_and_different_extractor_disabled",
			args: args{
				enabledExtractors:  []string{composerlock.Name},
				disabledExtractors: []string{packageslockjson.Name},
			},
			want: []string{composerlock.Name},
		},
		{
			name: "one_extractor_enabled_and_same_extractor_disabled",
			args: args{
				enabledExtractors:  []string{composerlock.Name},
				disabledExtractors: []string{composerlock.Name},
			},
			want: []string{},
		},
		//
		{
			name: "one_preset_enabled_and_nothing_disabled",
			args: args{
				enabledExtractors:  []string{"artifact"},
				disabledExtractors: nil,
			},
			want: []string{
				wheelegg.Name,
				archive.Name,
				gobinary.Name,
				nodemodules.Name,
				cargoauditable.Name,
				apk.Name,
				dpkg.Name,
			},
		},
		{
			name: "one_preset_enabled_and_different_preset_disabled",
			args: args{
				enabledExtractors:  []string{"artifact"},
				disabledExtractors: []string{"sbom"},
			},
			want: []string{
				wheelegg.Name,
				archive.Name,
				gobinary.Name,
				nodemodules.Name,
				cargoauditable.Name,
				apk.Name,
				dpkg.Name,
			},
		},
		{
			name: "one_preset_enabled_and_same_preset_disabled",
			args: args{
				enabledExtractors:  []string{"artifact"},
				disabledExtractors: []string{"artifact"},
			},
			want: []string{},
		},
		{
			name: "one_preset_enabled_and_some_extractors_disabled",
			args: args{
				enabledExtractors:  []string{"artifact"},
				disabledExtractors: []string{wheelegg.Name, archive.Name, cargoauditable.Name},
			},
			want: []string{
				gobinary.Name,
				nodemodules.Name,
				apk.Name,
				dpkg.Name,
			},
		},
		//
		{
			name: "multiple_presets_enabled_and_nothing_disabled",
			args: args{
				enabledExtractors:  []string{"artifact", "sbom"},
				disabledExtractors: []string{},
			},
			want: []string{
				spdx.Name,
				cdx.Name,
				wheelegg.Name,
				archive.Name,
				gobinary.Name,
				nodemodules.Name,
				cargoauditable.Name,
				apk.Name,
				dpkg.Name,
			},
		},
		//
		{
			name: "multiple_extractors_enabled_and_one_disabled_preset",
			args: args{
				enabledExtractors: []string{
					spdx.Name,
					archive.Name,
					gobinary.Name,
				},
				disabledExtractors: []string{"sbom"},
			},
			want: []string{
				archive.Name,
				gobinary.Name,
			},
		},
		{
			name: "multiple_extractors_enabled_and_disabled",
			args: args{
				enabledExtractors: []string{
					spdx.Name,
					archive.Name,
					gobinary.Name,
					cargoauditable.Name,
				},
				disabledExtractors: []string{
					cdx.Name,
					wheelegg.Name,
					gobinary.Name,
					apk.Name,
				},
			},
			want: []string{
				spdx.Name,
				archive.Name,
				cargoauditable.Name,
			},
		},
		//
		{
			name: "extractor_that_does_not_exist",
			args: args{
				enabledExtractors:  []string{"???"},
				disabledExtractors: nil,
			},
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ResolveEnabledExtractors(tt.args.enabledExtractors, tt.args.disabledExtractors)

			slices.Sort(tt.want)

			gotNames := make([]string, 0, len(got))
			for _, extractor := range got {
				gotNames = append(gotNames, extractor.Name())
			}

			slices.Sort(gotNames)

			if diff := cmp.Diff(tt.want, gotNames); diff != "" {
				t.Errorf("replaceJSONInput() diff (-want +got): %s", diff)
			}
		})
	}
}
