lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = 'dependency_spy'
  spec.version       = '0.1.0'
  spec.authors       = ['John Doe']
  spec.email         = ['email@example.pt']
  spec.summary       = 'Finds known vulnerabilities in your dependencies'
  spec.description   = '
    Finds known vulnerabilities in your dependencies
    Using rubysec/ruby-advisory-db, snyk.io, ossindex.net, nodesecurity.io
  '
  spec.homepage      = 'https://github.com/repo/dependency_spy'
  spec.license       = 'AGPL-3.0+'
  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features|database)/}) }
  spec.bindir        = 'bin'
  spec.executables   = ['dependency_spy', 'depspy']
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.5.5'

  spec.add_dependency 'thor', '1.3.2'
  spec.add_runtime_dependency 'timeout', '0.4.3'
  spec.add_runtime_dependency 'useragent', # comment to make sure the parser can handle this
                                # one more comment to make sure the parser can handle this
                                '0.16.11'
                                # even one more comment to make sure the parser can handle this
  spec.add_development_dependency 'zeitwerk', '>=2.7.1', '<10.0.0'
  spec.add_development_dependency 'websocket-extensions', [ # comment to make sure the parser can handle this
      '>=0.1.5',
      # one more comment to make sure the parser can handle this
      '<0.1.6'
      # even one more comment to make sure the parser can handle this
  ]
  spec.add_development_dependency 'websocket-driver'
end
