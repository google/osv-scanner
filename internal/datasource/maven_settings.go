package datasource

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/google/osv-scanner/v2/internal/cachedregexp"
)

// Maven settings.xml file parsing for registry authentication.
// https://maven.apache.org/settings.html

type MavenSettingsXML struct {
	Servers []MavenSettingsXMLServer `xml:"servers>server"`
}

type MavenSettingsXMLServer struct {
	ID       string `xml:"id"`
	Username string `xml:"username"`
	Password string `xml:"password"`
}

func ParseMavenSettings(path string) MavenSettingsXML {
	f, err := os.Open(path)
	if err != nil {
		return MavenSettingsXML{}
	}
	defer f.Close()

	var settings MavenSettingsXML
	if err := xml.NewDecoder(f).Decode(&settings); err != nil {
		return MavenSettingsXML{}
	}

	// interpolate strings with environment variables only
	// system properties are too hard to determine.
	re := cachedregexp.MustCompile(`\${env\.[^}]*}`)
	replFn := func(match string) string {
		// grab just the environment variable string
		env := match[len("${env.") : len(match)-1]

		// Environment variables on Windows are case-insensitive,
		// but Maven will only replace them if they are in all-caps.
		if runtime.GOOS == "windows" && strings.ContainsFunc(env, unicode.IsLower) {
			return match // No replacement.
		}

		if val, ok := os.LookupEnv(env); ok {
			return val
		}

		// Don't do any replacement if the environment variable isn't set
		return match
	}
	for i := range settings.Servers {
		settings.Servers[i].ID = re.ReplaceAllStringFunc(settings.Servers[i].ID, replFn)
		settings.Servers[i].Username = re.ReplaceAllStringFunc(settings.Servers[i].Username, replFn)
		settings.Servers[i].Password = re.ReplaceAllStringFunc(settings.Servers[i].Password, replFn)
	}

	return settings
}

// TODO: How to use with virtual filesystem + environment variables.
func globalMavenSettingsFile() string {
	// ${maven.home}/conf/settings.xml
	// Find ${maven.home} from the installed mvn binary
	mvnExec, err := exec.LookPath("mvn")
	if err != nil {
		return ""
	}
	mvnExec, err = filepath.EvalSymlinks(mvnExec)
	if err != nil {
		return ""
	}

	settings := filepath.Join(filepath.Dir(mvnExec), "..", "conf", "settings.xml")
	settings, err = filepath.Abs(settings)
	if err != nil {
		return ""
	}

	return settings
}

func userMavenSettingsFile() string {
	// ${user.home}/.m2/settings.xml
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	return filepath.Join(home, ".m2", "settings.xml")
}

var mavenSupportedAuths = []HTTPAuthMethod{AuthDigest, AuthBasic}

func MakeMavenAuth(globalSettings, userSettings MavenSettingsXML) map[string]*HTTPAuthentication {
	auth := make(map[string]*HTTPAuthentication)
	for _, s := range globalSettings.Servers {
		auth[s.ID] = &HTTPAuthentication{
			SupportedMethods: mavenSupportedAuths,
			AlwaysAuth:       false,
			Username:         s.Username,
			Password:         s.Password,
		}
	}

	for _, s := range userSettings.Servers {
		auth[s.ID] = &HTTPAuthentication{
			SupportedMethods: mavenSupportedAuths,
			AlwaysAuth:       false,
			Username:         s.Username,
			Password:         s.Password,
		}
	}

	return auth
}
