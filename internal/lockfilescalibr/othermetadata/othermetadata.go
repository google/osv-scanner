package othermetadata

type DepGroups interface {
	DepGroups() []string
}

// othermetadata.DepGroupMetadata is a metadata struct that only supports DepGroups
type DepGroupMetadata struct {
	DepGroupVals []string
}

var _ DepGroups = DepGroupMetadata{}

func (dgm DepGroupMetadata) DepGroups() []string {
	return dgm.DepGroupVals
}

// DistroVersionMetadata contains distro versions
// This is not meant to be used directly. The distro version should be retrieved
// from the Ecosystem() function.
type DistroVersionMetadata struct {
	DistroVersionStr string
}
