package maven

import (
	"testing"
)

// TestIsSafeRegistryURL verifies that isSafeRegistryURL correctly rejects
// URLs that could be used to perform SSRF attacks via pom.xml <repositories>.
func TestIsSafeRegistryURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid public HTTPS URL",
			url:     "https://repo.maven.apache.org/maven2",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL with path",
			url:     "https://repo1.maven.org/maven2/",
			wantErr: false,
		},
		{
			name:    "HTTP scheme rejected",
			url:     "http://repo.maven.apache.org/maven2",
			wantErr: true,
		},
		{
			name:    "file:// scheme rejected",
			url:     "file:///etc/passwd",
			wantErr: true,
		},
		{
			name:    "ftp:// scheme rejected",
			url:     "ftp://evil.example.com/maven2",
			wantErr: true,
		},
		{
			name:    "loopback address rejected via HTTP",
			url:     "http://127.0.0.1/latest/meta-data/",
			wantErr: true,
		},
		{
			name:    "EC2 metadata endpoint rejected",
			url:     "http://169.254.169.254/latest/meta-data/",
			wantErr: true,
		},
		{
			name:    "EC2 metadata endpoint with HTTPS still rejected (private IP)",
			url:     "https://169.254.169.254/latest/meta-data/",
			wantErr: true,
		},
		{
			name:    "private RFC1918 range rejected via HTTP",
			url:     "http://192.168.1.1/maven2",
			wantErr: true,
		},
		{
			name:    "private RFC1918 10.x range rejected via HTTP",
			url:     "http://10.0.0.1/maven2",
			wantErr: true,
		},
		{
			name:    "IPv6 loopback rejected",
			url:     "http://[::1]/maven2",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := isSafeRegistryURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("isSafeRegistryURL(%q) error = %v, wantErr = %v", tt.url, err, tt.wantErr)
			}
		})
	}
}
