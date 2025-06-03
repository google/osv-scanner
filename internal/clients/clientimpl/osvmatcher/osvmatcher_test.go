package osvmatcher

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/osvdev"

	"github.com/google/osv-scanner/v2/internal/scalibrextract/ecosystemmock"
)

func TestOSVMatcher_MatchVulnerabilities(t *testing.T) {
	type fields struct {
		Client              osvdev.OSVClient
		InitialQueryTimeout time.Duration
	}

	type args struct {
		ctx  context.Context
		pkgs []*extractor.Package
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		want    [][]*osvschema.Vulnerability
		wantErr error
	}{
		{
			name: "Timeout returns deadline exceeded error",
			fields: fields{
				Client:              *osvdev.DefaultClient(),
				InitialQueryTimeout: 1 * time.Millisecond,
			},
			args: args{
				ctx: context.Background(),
				pkgs: []*extractor.Package{
					{
						Name:    "lib1",
						Version: "1.0.1",
						Extractor: ecosystemmock.Extractor{
							MockEcosystem: "Go",
						},
					},
				},
			},
			want:    nil,
			wantErr: context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &OSVMatcher{
				Client:              tt.fields.Client,
				InitialQueryTimeout: tt.fields.InitialQueryTimeout,
			}

			got, err := matcher.MatchVulnerabilities(tt.args.ctx, tt.args.pkgs)
			if err != tt.wantErr && !errors.Is(err, tt.wantErr) {
				t.Errorf("OSVMatcher.MatchVulnerabilities() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("OSVMatcher.MatchVulnerabilities() = %v, want %v", got, tt.want)
			}
		})
	}
}
