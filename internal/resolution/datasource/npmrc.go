package datasource

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/osv-scanner/internal/cachedregexp"
	"gopkg.in/ini.v1"
)

type npmrcConfig struct {
	*ini.Section
}

func loadNpmrc(workdir string) (npmrcConfig, error) {
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
		return npmrcConfig{}, err
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
		return npmrcConfig{}, err
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
		return npmrcConfig{}, err
	}

	return npmrcConfig{fullNpmrc.Section("")}, nil
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

type NpmRegistryAuthInfo struct {
	authToken string
	auth      string
	username  string
	password  string
	// TODO: certfile, keyfile
}

func (authInfo NpmRegistryAuthInfo) AddToHeader(header http.Header) {
	switch {
	case authInfo.authToken != "":
		header.Set("Authorization", "Bearer "+authInfo.authToken)
	case authInfo.auth != "":
		header.Set("Authorization", "Basic "+authInfo.auth)
	case authInfo.username != "" && authInfo.password != "":
		// auth is base64-encoded "username:password"
		// password is stored already base64-encoded
		authBytes := []byte(authInfo.username + ":")
		b, err := base64.StdEncoding.DecodeString(authInfo.password)
		if err != nil {
			// TODO: mimic the behaviour of node's Buffer.from(s, 'base64').toString()
			// e.g. ignore invalid characters, stop parsing after first '=', just never throw an error
			panic(fmt.Sprintf("Unable to decode registry password: %v", err))
		}
		authBytes = append(authBytes, b...)
		auth := base64.StdEncoding.EncodeToString(authBytes)
		header.Set("Authorization", "Basic "+auth)
	}
}

// Implementation of npm registry auth matching, adapted from npm-registry-fetch
// https://github.com/npm/npm-registry-fetch/blob/237d33b45396caa00add61e0549cf09fbf9deb4f/lib/auth.js
type NpmRegistryAuthOpts map[string]string

var npmAuthFields = [...]string{":_authToken", ":_auth", ":username", ":_password"} // reference of the relevant config key suffixes

func (opts NpmRegistryAuthOpts) getRegAuth(regKey string) (NpmRegistryAuthInfo, bool) {
	if token, ok := opts[regKey+":_authToken"]; ok {
		return NpmRegistryAuthInfo{authToken: token}, true
	}
	if auth, ok := opts[regKey+":_auth"]; ok {
		return NpmRegistryAuthInfo{auth: auth}, true
	}
	if user, ok := opts[regKey+":username"]; ok {
		if pass, ok := opts[regKey+":_password"]; ok {
			return NpmRegistryAuthInfo{username: user, password: pass}, true
		}
	}
	// TODO: certfile / keyfile

	return NpmRegistryAuthInfo{}, false
}

func (opts NpmRegistryAuthOpts) GetAuth(uri string) NpmRegistryAuthInfo {
	parsed, err := url.Parse(uri)
	if err != nil {
		return NpmRegistryAuthInfo{}
	}
	regKey := "//" + parsed.Host + parsed.EscapedPath()
	for regKey != "//" {
		if authInfo, ok := opts.getRegAuth(regKey); ok {
			return authInfo
		}

		// can be either //host/some/path/:_auth or //host/some/path:_auth
		// walk up by removing EITHER what's after the slash OR the slash itself
		var found bool
		if regKey, found = strings.CutSuffix(regKey, "/"); !found {
			regKey = regKey[:strings.LastIndex(regKey, "/")+1]
		}
	}

	return NpmRegistryAuthInfo{}
}

// urlPathEscapeLower is url.PathEscape but with lowercase letters in hex codes (matching npm's behaviour)
// e.g. "@reg/pkg" -> "@reg%2fpkg"
func urlPathEscapeLower(s string) string {
	escaped := url.PathEscape(s)
	re := cachedregexp.MustCompile(`%[0-9A-F]{2}`)

	return re.ReplaceAllStringFunc(escaped, strings.ToLower)
}

type NpmRegistryConfig struct {
	ScopeURLs map[string]string   // map of @scope to registry URL
	RegOpts   NpmRegistryAuthOpts // the full key-value pairs of relevant npmrc config options.
}

func LoadNpmRegistryConfig(workdir string) (NpmRegistryConfig, error) {
	npmrc, err := loadNpmrc(workdir)
	if err != nil {
		return NpmRegistryConfig{}, err
	}

	return parseNpmRegistryInfo(npmrc), nil
}

// BuildRequest creates the http request to the corresponding npm registry api
// urlComponents should be (package) or (package, version)
func (r NpmRegistryConfig) BuildRequest(ctx context.Context, urlComponents ...string) (*http.Request, error) {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	r.RegOpts.GetAuth(reqURL).AddToHeader(req.Header)

	return req, nil
}

func parseNpmRegistryInfo(npmrc npmrcConfig) NpmRegistryConfig {
	config := NpmRegistryConfig{
		ScopeURLs: map[string]string{"": "https://registry.npmjs.org/"}, // set the default registry
		RegOpts:   make(NpmRegistryAuthOpts),
	}

	for _, k := range npmrc.Keys() {
		name := k.Name()
		value := os.ExpandEnv(k.String())
		// TODO: npm config replaces only ${VAR}, not $VAR
		// and if VAR is unset, it will leave the string as "${VAR}"

		if name == "registry" {
			config.ScopeURLs[""] = value
			continue
		}
		if scope, ok := strings.CutSuffix(name, ":registry"); ok {
			config.ScopeURLs[scope] = value
			continue
		}
		for _, f := range npmAuthFields {
			if strings.HasSuffix(name, f) {
				config.RegOpts[name] = value
			}
		}
	}

	return config
}
