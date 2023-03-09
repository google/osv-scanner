#!/usr/bin/env ruby

require "rubygems/version"
require "open-uri"
require "json"
require "zip"

def download_rubygems_db
  URI.open("https://osv-vulnerabilities.storage.googleapis.com/RubyGems/all.zip") do |zip|
    File.open("rubygems-db.zip", "wb") { |f| f.write(zip.read) }
  end
end

def extract_packages_with_versions(osvs)
  packages = {}

  osvs.each do |osv|
    osv["affected"].each do |affected|
      package = affected["package"]["name"]

      packages[package] ||= []
      affected.fetch("versions", []).each do |version|
        packages[package] << Gem::Version.new(version)
      end
    end
  end

  packages.map { |k, v| [k, v.uniq.sort] }.to_h
end

def compare_version(v1, op, v2)
  op = "==" if op == "="

  Gem::Version.new(v1).method(op).call(Gem::Version.new(v2))
end

# @param [Array<String>] lines
# @return [Boolean]
def compare_versions(lines, select = :all)
  has_any_failed = false

  lines.each do |line|
    line = line.strip

    next if line.empty? || line.start_with?("#") || line.start_with?("//")

    parts = line.split(" ")
    v1 = parts[0]
    op = parts[1]
    v2 = parts[2]

    r = compare_version(v1, op, v2)

    has_any_failed = true unless r

    next if select == :failures && r == true
    next if select == :successes && r != true

    color = r ? "\033[92m" : "\033[91m"
    rs = r ? "T" : "F"
    puts "#{color}#{rs}\033[0m: \033[93m#{line}\033[0m"
  end

  has_any_failed
end

def compare_versions_in_file(filepath, select = :all)
  compare_versions(File.readlines(filepath), select)
end

def generate_version_compares(versions)
  comparisons = []

  versions.each_with_index do |version, i|
    next if i == 0

    op = "<"
    op = "=" if versions[i - 1] == version

    comparisons << "#{versions[i - 1]} #{op} #{version}"
  end

  comparisons
end

def generate_package_compares(packages)
  comparisons = []

  packages.each { |_, versions| comparisons.concat(generate_version_compares(versions)) }

  comparisons
end

def fetch_packages_versions
  download_rubygems_db

  osvs = Zip::File.open("rubygems-db.zip").map { |f| JSON.load(f.get_input_stream.read) }

  extract_packages_with_versions(osvs)
end

outfile = "internal/semantic/fixtures/rubygems-versions-generated.txt"

packs = fetch_packages_versions

File.open(outfile, "w") { |f| f.write(generate_package_compares(packs).uniq.join("\n") + "\n") }

# set this to either "failures" or "successes" to only have those comparison results
# printed; setting it to anything else will have all comparison results printed
show = ENV.fetch("VERSION_GENERATOR_PRINT", :failures).to_sym

did_any_fail = compare_versions_in_file(outfile, show)

exit(1) if did_any_fail
