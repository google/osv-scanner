# makes the osv-scanner version tracked in Go
# available via site.scanner_version in docs
Jekyll::Hooks.register :site, :after_init do |site|
  path = File.expand_path("../internal/version/version.go", site.source)
  match = File.read(path).match(/OSVVersion\s*=\s*"([^"]+)"/)

  raise "could not find OSVVersion in #{path}" unless match

  site.config["scanner_version"] = match[1]
end
