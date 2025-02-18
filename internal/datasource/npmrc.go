package datasource

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/v2/internal/cachedregexp"
	"gopkg.in/ini.v1"
)

type NpmrcConfig map[string]string

func loadNpmrc(workdir string) (NpmrcConfig, error) {
	// Find & parse the 4 npmrc files (builtin, global, user, project) + values set in environment variables
	// https://docs.npmjs.com/cli/v10/configuring-npm/npmrc
	// https://docs.npmjs.com/cli/v10/using-npm/config

	// project npmrc is always in ./.npmrc
	projectFile, _ := filepath.Abs(filepath.Join(workdir, ".npmrc"))
	// TODO: Pass in environment variables so we can sandbox tests
	builtinFile := builtinNpmrc()
	envVarOpts, _ := envVarNpmrc()

	opts := ini.LoadOptions{
		Loose:              true, // ignore missing files
		KeyValueDelimiters: "=",  // default delimiters are "=:", but npmrc uses : in some keys
	}
	// Make use of data overwriting to load the correct values
	fullNpmrc, err := ini.LoadSources(opts, builtinFile, projectFile, envVarOpts)
	if err != nil {
		return nil, err
	}

	// user npmrc is either set as userconfig, or ${HOME}/.npmrc
	// though userconfig cannot be set in the user or global npmrcs
	var userFile string
	switch {
	case fullNpmrc.Section("").HasKey("userconfig"):
		userFile = os.ExpandEnv(fullNpmrc.Section("").Key("userconfig").String())
		// TODO: npm config replaces only ${VAR}, not $VAR
		// and if VAR is unset, it will leave the string as "${VAR}"
	default:
		homeDir, err := os.UserHomeDir()
		if err == nil { // only set userFile if homeDir exists
			userFile = filepath.Join(homeDir, ".npmrc")
		}
	}

	// reload the npmrc files with the user file included
	fullNpmrc, err = ini.LoadSources(opts, builtinFile, userFile, projectFile, envVarOpts)
	if err != nil {
		return nil, err
	}

	var globalFile string
	// global npmrc is either set as globalconfig, prefix/etc/npmrc, ${PREFIX}/etc/npmrc
	// cannot be set within the global npmrc itself
	switch {
	case fullNpmrc.Section("").HasKey("globalconfig"):
		globalFile = os.ExpandEnv(fullNpmrc.Section("").Key("globalconfig").String())
	// TODO: Windows
	case fullNpmrc.Section("").HasKey("prefix"):
		prefix := os.ExpandEnv(fullNpmrc.Section("").Key("prefix").String())
		globalFile, _ = filepath.Abs(filepath.Join(prefix, "etc", "npmrc"))
	case os.Getenv("PREFIX") != "":
		globalFile, _ = filepath.Abs(filepath.Join(os.Getenv("PREFIX"), "etc", "npmrc"))
	default:
		globalFile = filepath.Join("/etc", "npmrc") // TODO: what should this be actually?
	}

	// return final joined config, with correct overriding order
	fullNpmrc, err = ini.LoadSources(opts, builtinFile, globalFile, userFile, projectFile, envVarOpts)
	if err != nil {
		return nil, err
	}

	return fullNpmrc.Section("").KeysHash(), nil
}

func envVarNpmrc() ([]byte, error) {
	// parse npm config settings that were set in environment variables,
	// returns a ini.Load()-able byte array of the values

	iniFile := ini.Empty()
	// npm config environment variables seem to be case-insensitive, interpreted in lowercase
	// get all the matching environment variables and their values
	const envPrefix = "npm_config_"
	for _, env := range os.Environ() {
		split := strings.SplitN(env, "=", 2)
		k := strings.ToLower(split[0])
		v := split[1]
		if s, ok := strings.CutPrefix(k, envPrefix); ok {
			if _, err := iniFile.Section("").NewKey(s, v); err != nil {
				return nil, err
			}
		}
	}
	var buf bytes.Buffer
	_, err := iniFile.WriteTo(&buf)

	return buf.Bytes(), err
}

func builtinNpmrc() string {
	// builtin is always at /path/to/npm/npmrc
	npmExec, err := exec.LookPath("npm")
	if err != nil {
		return ""
	}
	npmExec, err = filepath.EvalSymlinks(npmExec)
	if err != nil {
		return ""
	}
	npmrc := filepath.Join(filepath.Dir(npmExec), "..", "npmrc")
	npmrc, err = filepath.Abs(npmrc)
	if err != nil {
		return ""
	}

	return npmrc
}

// NpmRegistryAuths handles npm registry authentication in a manner similar to npm-registry-fetch
// https://github.com/npm/npm-registry-fetch/blob/237d33b45396caa00add61e0549cf09fbf9deb4f/lib/auth.js
type NpmRegistryAuths map[string]*HTTPAuthentication

func (auths NpmRegistryAuths) GetAuth(uri string) *HTTPAuthentication {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil
	}
	regKey := "//" + parsed.Host + parsed.EscapedPath()
	for regKey != "//" {
		if httpAuth, ok := auths[regKey]; ok {
			// Make sure this httpAuth actually has the necessary fields to construct an auth.
			// i.e. it's not valid if only Username or only Password is set
			if httpAuth.BearerToken != "" ||
				httpAuth.BasicAuth != "" ||
				(httpAuth.Username != "" && httpAuth.Password != "") {
				return httpAuth
			}
		}

		// can be either //host/some/path/:_auth or //host/some/path:_auth
		// walk up by removing EITHER what's after the slash OR the slash itself
		var found bool
		if regKey, found = strings.CutSuffix(regKey, "/"); !found {
			regKey = regKey[:strings.LastIndex(regKey, "/")+1]
		}
	}

	return nil
}

// urlPathEscapeLower is url.PathEscape but with lowercase letters in hex codes (matching npm's behaviour)
// e.g. "@reg/pkg" -> "@reg%2fpkg"
func urlPathEscapeLower(s string) string {
	escaped := url.PathEscape(s)
	re := cachedregexp.MustCompile(`%[0-9A-F]{2}`)

	return re.ReplaceAllStringFunc(escaped, strings.ToLower)
}

type NpmRegistryConfig struct {
	ScopeURLs map[string]string // map of @scope to registry URL
	Auths     NpmRegistryAuths  // auth info per npm registry URI
}

func LoadNpmRegistryConfig(workdir string) (NpmRegistryConfig, error) {
	npmrc, err := loadNpmrc(workdir)
	if err != nil {
		return NpmRegistryConfig{}, err
	}

	return ParseNpmRegistryInfo(npmrc), nil
}

// MakeRequest makes the http request to the corresponding npm registry api (with auth).
// urlComponents should be (package) or (package, version)
func (r NpmRegistryConfig) MakeRequest(ctx context.Context, httpClient *http.Client, urlComponents ...string) (*http.Response, error) {
	if len(urlComponents) == 0 {
		return nil, errors.New("no package specified in npm request")
	}
	// find the corresponding registryInfo for the package's scope
	pkg := urlComponents[0]
	scope := ""
	if strings.HasPrefix(pkg, "@") {
		scope, _, _ = strings.Cut(pkg, "/")
	}
	baseURL, ok := r.ScopeURLs[scope]
	if !ok {
		// no specific rules for this scope, use the default scope
		baseURL = r.ScopeURLs[""]
	}

	for i := range urlComponents {
		urlComponents[i] = urlPathEscapeLower(urlComponents[i])
	}
	reqURL, err := url.JoinPath(baseURL, urlComponents...)
	if err != nil {
		return nil, err
	}

	return r.Auths.GetAuth(reqURL).Get(ctx, httpClient, reqURL)
}

var npmSupportedAuths = []HTTPAuthMethod{AuthBearer, AuthBasic}

func ParseNpmRegistryInfo(npmrc NpmrcConfig) NpmRegistryConfig {
	config := NpmRegistryConfig{
		ScopeURLs: map[string]string{"": "https://registry.npmjs.org/"}, // set the default registry
		Auths:     make(map[string]*HTTPAuthentication),
	}

	getOrInitAuth := func(key string) *HTTPAuthentication {
		if auth, ok := config.Auths[key]; ok {
			return auth
		}
		auth := &HTTPAuthentication{
			SupportedMethods: npmSupportedAuths,
			AlwaysAuth:       true,
		}
		config.Auths[key] = auth

		return auth
	}

	for name, value := range npmrc {
		var part1, part2 string
		// must split on the last ':' in case e.g. '//localhost:8080/:_auth=xyz'
		if idx := strings.LastIndex(name, ":"); idx >= 0 {
			part1, part2 = name[:idx], name[idx+1:]
		}
		value := os.ExpandEnv(value)
		// TODO: npm config replaces only ${VAR}, not $VAR
		// and if VAR is unset, it will leave the string as "${VAR}"
		switch {
		case name == "registry": // registry=...
			config.ScopeURLs[""] = value
		case part2 == "registry": // @scope:registry=...
			config.ScopeURLs[part1] = value
		case part2 == "_authToken": // //uri:_authToken=...
			getOrInitAuth(part1).BearerToken = value
		case part2 == "_auth": // //uri:_auth=...
			getOrInitAuth(part1).BasicAuth = value
		case part2 == "username": // //uri:username=...
			getOrInitAuth(part1).Username = value
		case part2 == "_password": // //uri:_password=<base64>
			password, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				// TODO: mimic the behaviour of node's Buffer.from(s, 'base64').toString()
				// e.g. ignore invalid characters, stop parsing after first '=', just never throw an error
				break
			}
			getOrInitAuth(part1).Password = string(password)
		}
	}

	return config
}
