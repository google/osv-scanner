package osvmatcher

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	dpkgmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	rpmmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	"github.com/google/osv-scalibr/purl"
)

func dpkgPkg(name, source, version, osID, osVersionID string) *extractor.Package {
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypeDebian,
		Metadata: &dpkgmetadata.Metadata{
			PackageName: name,
			SourceName:  source,
			OSID:        osID,
			OSVersionID: osVersionID,
		},
	}
}

func TestRoutedQueryPackage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		pkg           *extractor.Package
		wantNil       bool
		wantName      string
		wantEcosystem string
	}{
		{
			name:          "marked_ubuntu_routes_to_tuxcare_with_binary_name",
			pkg:           dpkgPkg("squid-cgi", "squid", "3.5.27-1ubuntu1.14+tuxcare.els3", "ubuntu", "18.04"),
			wantName:      "squid-cgi",
			wantEcosystem: "TuxCare:Ubuntu:18.04",
		},
		{
			name:          "marked_debian_routes_to_tuxcare",
			pkg:           dpkgPkg("binutils", "binutils", "2.31.1-16+tuxcare.els11", "debian", "10"),
			wantName:      "binutils",
			wantEcosystem: "TuxCare:Debian:10",
		},
		{
			name:    "unmarked_package_returns_nil",
			pkg:     dpkgPkg("squid", "squid", "3.5.27-1ubuntu1.14", "ubuntu", "18.04"),
			wantNil: true,
		},
		{
			name:    "marked_but_unknown_distro_returns_nil",
			pkg:     dpkgPkg("foo", "foo", "1.0+tuxcare.els1", "fedora", "39"),
			wantNil: true,
		},
		{
			name:    "marked_but_missing_version_id_returns_nil",
			pkg:     dpkgPkg("foo", "foo", "1.0+tuxcare.els1", "ubuntu", ""),
			wantNil: true,
		},
		{
			name:          "marked_tilde_separator_routes",
			pkg:           dpkgPkg("ca-certificates", "ca-certificates", "20221215~16.04.1ubuntu0.1~tuxcare.els1", "ubuntu", "16.04"),
			wantName:      "ca-certificates",
			wantEcosystem: "TuxCare:Ubuntu:16.04",
		},
		{
			name:          "marked_dot_separator_routes",
			pkg:           dpkgPkg("foo", "foo", "1.0.tuxcare.els1", "ubuntu", "16.04"),
			wantName:      "foo",
			wantEcosystem: "TuxCare:Ubuntu:16.04",
		},
		{
			name:    "non_dpkg_marker_in_version_not_routed",
			pkg:     &extractor.Package{Name: "leftpad", Version: "1.0.0+tuxcare.1", PURLType: purl.TypeNPM},
			wantNil: true,
		},
	}

	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := routedQueryPackage(tt.pkg)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("routedQueryPackage() = %#v, want nil", got)
				}

				return
			}
			if got == nil {
				t.Fatalf("routedQueryPackage() = nil, want {%q, %q}", tt.wantName, tt.wantEcosystem)
			}
			if got.GetName() != tt.wantName || got.GetEcosystem() != tt.wantEcosystem {
				t.Fatalf("routedQueryPackage() = {%q, %q}, want {%q, %q}",
					got.GetName(), got.GetEcosystem(), tt.wantName, tt.wantEcosystem)
			}
		})
	}
}

func rpmPkg(name, version, osID, osVersionID, osName, cpe string) *extractor.Package {
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypeRPM,
		Metadata: &rpmmetadata.Metadata{
			PackageName:  name,
			OSID:         osID,
			OSVersionID:  osVersionID,
			OSName:       osName,
			OSPrettyName: osName,
			OSCPEName:    cpe,
		},
	}
}

func TestRoutedQueryPackage_RPM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		pkg           *extractor.Package
		wantNil       bool
		wantName      string
		wantEcosystem string
	}{
		{
			name:          "almalinux_uses_full_version_id",
			pkg:           rpmPkg("gnutls", "3.7.6-21.el9_2.tuxcare.els2", "almalinux", "9.2", "AlmaLinux", "cpe:/o:almalinux:almalinux:9::baseos"),
			wantName:      "gnutls",
			wantEcosystem: "TuxCare:AlmaLinux:9.2",
		},
		{
			name:          "rhel_uses_major_version",
			pkg:           rpmPkg("bash", "4.4.20-4.el8_4.tuxcare.els1", "rhel", "8.4", "Red Hat Enterprise Linux", "cpe:/o:redhat:enterprise_linux:8::baseos"),
			wantName:      "bash",
			wantEcosystem: "TuxCare:RHEL:8",
		},
		{
			name:          "oracle_uses_major_version",
			pkg:           rpmPkg("openssl", "1.0.2k-25.el7.tuxcare.els3", "ol", "7.9", "Oracle Linux Server", "cpe:/o:oracle:linux:7:9:server"),
			wantName:      "openssl",
			wantEcosystem: "TuxCare:OracleLinux:7",
		},
		{
			name:          "centos7_uses_major_version",
			pkg:           rpmPkg("glibc", "2.17-326.el7.tuxcare.els2", "centos", "7", "CentOS Linux", "cpe:/o:centos:centos:7"),
			wantName:      "glibc",
			wantEcosystem: "TuxCare:CentOS:7",
		},
		{
			name:          "centos_stream_detected_via_os_name",
			pkg:           rpmPkg("curl", "7.61.1-22.el8.tuxcare.els14", "centos", "8", "CentOS Stream", "cpe:/o:centos:centos:8"),
			wantName:      "curl",
			wantEcosystem: "TuxCare:CentOS-Stream:8",
		},
		{
			name:    "unmarked_rpm_returns_nil",
			pkg:     rpmPkg("gnutls", "3.7.6-21.el9_2", "almalinux", "9.2", "AlmaLinux", ""),
			wantNil: true,
		},
		{
			// CentOS-8 non-Stream is deferred (Phase 2b): channel minor not recoverable.
			name:    "centos8_marked_but_no_el_token_returns_nil",
			pkg:     rpmPkg("weird", "1.0-1.tuxcare.els1", "centos", "8", "CentOS Linux", ""),
			wantNil: true,
		},
		{
			// CentOS-8 non-Stream is deferred even when an el token is present.
			name:    "centos8_non_stream_deferred_even_with_el_token",
			pkg:     rpmPkg("openssl", "1.1.1g-15.el8_4.tuxcare.els8", "centos", "8", "CentOS Linux", "cpe:/o:centos:centos:8"),
			wantNil: true,
		},
		{
			name:    "unknown_rpm_distro_returns_nil",
			pkg:     rpmPkg("foo", "1.0-1.fc39.tuxcare.els1", "fedora", "39", "Fedora", ""),
			wantNil: true,
		},
	}

	for i := range tests {
		tt := tests[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := routedQueryPackage(tt.pkg)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("routedQueryPackage() = %#v, want nil", got)
				}

				return
			}
			if got == nil {
				t.Fatalf("routedQueryPackage() = nil, want {%q, %q}", tt.wantName, tt.wantEcosystem)
			}
			if got.GetName() != tt.wantName || got.GetEcosystem() != tt.wantEcosystem {
				t.Fatalf("routedQueryPackage() = {%q, %q}, want {%q, %q}",
					got.GetName(), got.GetEcosystem(), tt.wantName, tt.wantEcosystem)
			}
		})
	}
}

// A routed TuxCare RPM query composes routing with the general epoch handling:
// the query targets the TuxCare ecosystem and carries the package epoch, so
// osv.dev orders versions correctly. This is why TuxCare recognition depends on
// the RPM epoch fix.
func TestPkgToQuery_RoutedRPMCarriesEpoch(t *testing.T) {
	t.Parallel()

	pkg := &extractor.Package{
		Name:     "openssl-libs",
		Version:  "3.2.2-7.el9_6.tuxcare.1.els7",
		PURLType: purl.TypeRPM,
		Metadata: &rpmmetadata.Metadata{
			PackageName: "openssl-libs",
			Epoch:       1,
			OSID:        "almalinux",
			OSVersionID: "9.6",
			OSName:      "AlmaLinux",
		},
	}

	query := pkgToQuery(pkg)
	if query == nil {
		t.Fatal("pkgToQuery() = nil, want a routed query")
	}
	if got := query.GetPackage().GetEcosystem(); got != "TuxCare:AlmaLinux:9.6" {
		t.Errorf("query ecosystem = %q, want %q", got, "TuxCare:AlmaLinux:9.6")
	}
	if got, want := query.GetVersion(), "1:3.2.2-7.el9_6.tuxcare.1.els7"; got != want {
		t.Errorf("query version = %q, want %q (epoch-qualified)", got, want)
	}
}
