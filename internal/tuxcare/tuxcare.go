// Package tuxcare holds the vendor-specific rules for recognizing TuxCare ELS
// advisories (marker detection, distro/ecosystem mapping, and CentOS-8 channel
// detection). Shared osv-scanner code references only the exported entrypoints.
package tuxcare

import (
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/binary/proto/metadata"
	"github.com/google/osv-scalibr/extractor"
	apkmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	dpkgmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	rpmmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"github.com/google/osv-scanner/v2/internal/cachedregexp"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

//nolint:gochecknoinits // Using init to register metadata is by design (mirrors osvscannerjson/metadata.go)
func init() {
	// ChannelMarkerMetadata is a transient type stripped before matching/output.
	// RegisterNil ensures proto conversion silently produces nil instead of
	// ErrStructNotRegistered when scalibrSR still contains the marker package.
	metadata.RegisterNil[*ChannelMarkerMetadata]()
}

// Marker matches the installed version of a TuxCare-rebuilt package (separator-tolerant).
var Marker = cachedregexp.MustCompile(`[-.+~]tuxcare`)

// EcosystemPrefix is prepended to a base ecosystem to form a TuxCare overlay
// ecosystem (e.g. "AlmaLinux:9.6" -> "TuxCare:AlmaLinux:9.6").
const EcosystemPrefix = "TuxCare:"

// BaseEcosystem strips the TuxCare overlay prefix, returning the base ecosystem
// a TuxCare advisory reconciles against ("TuxCare:AlmaLinux:9.6" -> "AlmaLinux:9.6").
// Ecosystems without the prefix are returned unchanged. This mirrors how Ubuntu
// Pro/LTS variant suffixes are normalized away when matching advisories to packages.
func BaseEcosystem(ecosystem string) string {
	return strings.TrimPrefix(ecosystem, EcosystemPrefix)
}

// distroNames maps os-release IDs to the TuxCare deb distro name.
var distroNames = map[string]string{
	"ubuntu": "Ubuntu",
	"debian": "Debian",
}

// OverlayPackage returns the TuxCare ecosystem coordinates (binary name + ecosystem)
// for an OS package, or nil if the package's OS is not a supported TuxCare distro.
func OverlayPackage(pkg *extractor.Package) *osvschema.Package {
	distro, version := distroAndVersion(pkg)
	if distro == "" || version == "" {
		return nil
	}
	name := osPackageName(pkg)
	if name == "" {
		return nil
	}

	return &osvschema.Package{Name: name, Ecosystem: EcosystemPrefix + distro + ":" + version}
}

// QueryVersion returns the version to send to osv.dev for a TuxCare-routed
// package. TuxCare ELS advisory records encode the RPM epoch, but scalibr keeps
// it in rpmmetadata.Metadata.Epoch, separate from the version string; prepend it
// when non-zero (e.g. "3.2.2-7.el9_6" -> "1:3.2.2-7.el9_6") so osv.dev does not
// read the missing epoch as 0 and report already-fixed advisories as unfixed.
// deb packages carry any epoch inline in the version (non-RPM metadata), so they
// pass through unchanged. Only routing (OverlayPackage) reaches this, so no
// ecosystem allowlist is needed: every TuxCare ecosystem encodes the epoch.
func QueryVersion(pkg *extractor.Package) string {
	if m, ok := pkg.Metadata.(*rpmmetadata.Metadata); ok && m.Epoch > 0 {
		return strconv.Itoa(m.Epoch) + ":" + pkg.Version
	}

	return pkg.Version
}

func distroAndVersion(pkg *extractor.Package) (distro, version string) {
	switch m := pkg.Metadata.(type) {
	case *dpkgmetadata.Metadata:
		return distroNames[m.OSID], m.OSVersionID
	case *rpmmetadata.Metadata:
		return rpmDistroAndVersion(m)
	}

	return "", ""
}

func rpmDistroAndVersion(m *rpmmetadata.Metadata) (distro, version string) {
	switch m.OSID {
	case "almalinux":
		return "AlmaLinux", m.OSVersionID
	case "rhel":
		return "RHEL", majorVersion(m.OSVersionID)
	case "ol":
		return "OracleLinux", majorVersion(m.OSVersionID)
	case "centos":
		if isCentOSStream(m) {
			return "CentOS-Stream", majorVersion(m.OSVersionID)
		}
		switch majorVersion(m.OSVersionID) {
		case "6", "7":
			return "CentOS", majorVersion(m.OSVersionID)
		default:
			// CentOS 8.x: the channel minor (8.4/8.5) is supplied by the ELS-repo
			// channel enricher, which stamps a "8.4"/"8.5" OSVersionID. A bare "8"
			// (no repo file found) does not route. See EnrichHostContext.
			if strings.Contains(m.OSVersionID, ".") {
				return "CentOS", m.OSVersionID
			}

			return "", ""
		}
	}

	return "", ""
}

func majorVersion(v string) string {
	major, _, _ := strings.Cut(v, ".")
	return major
}

func isCentOSStream(m *rpmmetadata.Metadata) bool {
	for _, s := range []string{m.OSName, m.OSPrettyName, m.OSCPEName} {
		if strings.Contains(strings.ToLower(s), "stream") {
			return true
		}
	}

	return false
}

// osPackageName returns the binary package name from OS-package metadata. It
// mirrors imodels.OSPackageName without creating an import cycle.
func osPackageName(pkg *extractor.Package) string {
	if m, ok := pkg.Metadata.(*apkmetadata.Metadata); ok {
		return m.PackageName
	}
	if m, ok := pkg.Metadata.(*dpkgmetadata.Metadata); ok {
		return m.PackageName
	}
	if m, ok := pkg.Metadata.(*rpmmetadata.Metadata); ok {
		return m.PackageName
	}

	return ""
}

// RepoFileNames maps a TuxCare CentOS-8 ELS repo filename to its channel minor.
// This is the only reliable signal for the CentOS-8 channel (os-release is "8").
var RepoFileNames = map[string]string{
	"centos8.4-els.repo": "8.4",
	"centos8.5-els.repo": "8.5",
}

// ChannelMarkerMetadata is attached by the repo-file extractor to a synthetic marker
// package to carry the detected host channel to the enricher. It never reaches the
// matcher or output (EnrichHostContext strips it).
type ChannelMarkerMetadata struct {
	Channel string // e.g. "8.4" or "8.5"
}

// IsProtoable satisfies the metadata.Protoable interface required by extractor.Package.Metadata.
func (*ChannelMarkerMetadata) IsProtoable() {}

// EnrichHostContext derives host-level facts from marker packages in the inventory
// and applies them, returning the inventory with marker packages removed. Currently:
// stamps the CentOS-8 ELS channel minor onto CentOS-8 RPM packages so routing can
// resolve TuxCare:CentOS:8.4 / :8.5.
//
// If multiple markers report conflicting channels (should not happen on a real host),
// a warning is logged and no stamping is performed (safe no-route rather than wrong-route).
func EnrichHostContext(pkgs []*extractor.Package) []*extractor.Package {
	channel := ""
	conflict := false
	for _, p := range pkgs {
		if m, ok := p.Metadata.(*ChannelMarkerMetadata); ok && m.Channel != "" {
			if channel == "" {
				channel = m.Channel
			} else if channel != m.Channel {
				conflict = true
			}
		}
	}

	if conflict {
		cmdlogger.Warnf("tuxcare: conflicting CentOS-8 ELS channel markers detected; skipping channel stamping to avoid wrong-route")
		channel = ""
	}

	out := make([]*extractor.Package, 0, len(pkgs))
	for _, p := range pkgs {
		if _, ok := p.Metadata.(*ChannelMarkerMetadata); ok {
			continue // strip the marker
		}
		if channel != "" {
			stampCentOS8Channel(p, channel)
		}
		out = append(out, p)
	}

	return out
}

// stampCentOS8Channel sets the channel minor as OSVersionID on a CentOS-8 RPM package
// (which otherwise only knows "8"), so rpmDistroAndVersion can route it.
func stampCentOS8Channel(pkg *extractor.Package, channel string) {
	m, ok := pkg.Metadata.(*rpmmetadata.Metadata)
	if !ok || m.OSID != "centos" || isCentOSStream(m) || majorVersion(m.OSVersionID) != "8" {
		return
	}
	m.OSVersionID = channel
}
