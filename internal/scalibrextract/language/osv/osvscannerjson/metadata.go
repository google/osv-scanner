package osvscannerjson

import (
	"github.com/google/osv-scalibr/binary/proto/metadata"
	pb "github.com/google/osv-scanner/v2/internal/scalibrextract/language/osv/osvscannerjson/proto"
	"github.com/google/osv-scanner/v2/pkg/models"
)

//nolint:gochecknoinits // Using init to register the metadata is by design
func init() {
	metadata.Register(ToStruct, ToProto)
}

// Metadata holds the metadata for osvscanner.json
type Metadata struct {
	Ecosystem  string
	SourceInfo models.SourceInfo
}

// ToProto converts the metadata struct to the OSVScannerJsonMetadata proto.
func ToProto(m *Metadata) *pb.OSVScannerJsonMetadata {
	return &pb.OSVScannerJsonMetadata{
		Ecosystem: m.Ecosystem,
		SourceInfo: &pb.SourceInfo{
			Path: m.SourceInfo.Path,
			Type: string(m.SourceInfo.Type),
		},
	}
}

// IsProtoable marks the struct as a metadata type.
func (m *Metadata) IsProtoable() {}

// ToStruct converts the OSVScannerJsonMetadata proto to the Metadata struct.
func ToStruct(m *pb.OSVScannerJsonMetadata) *Metadata {
	return &Metadata{
		Ecosystem: m.GetEcosystem(),
		SourceInfo: models.SourceInfo{
			Path: m.GetSourceInfo().GetPath(),
			Type: models.SourceType(m.GetSourceInfo().GetType()),
		},
	}
}
