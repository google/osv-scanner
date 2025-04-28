Gem::Specification.new do |spec|
  spec.name          = "example"
  spec.version       = "0.1.0"
  spec.summary       = "An example gem"
  spec.authors       = ["Example Author"]
  spec.email         = ["example@example.com"]
  spec.files         = ["lib/example.rb"]

  spec.add_runtime_dependency "rake", "~> 13.0"
  spec.add_runtime_dependency "nonexistent_gem", "~> 1.0"
end
