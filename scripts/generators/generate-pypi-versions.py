#!/usr/bin/env python3

import json
import operator
import os
import packaging.version
import sys
import urllib.request
import zipfile

# this requires you run "pip install packaging" - have to be careful about versions too
# because of the "legacy version" stuff

# An array of version comparisons that are known to be unsupported and so
# should be commented out in the generated fixture.
#
# Generally this is because the native implementation has a suspected bug
# that causes the comparison to return incorrect results, and so supporting
# such comparisons in the detector would in fact be wrong.
UNSUPPORTED_COMPARISONS = []


def is_unsupported_comparison(line):
  return line in UNSUPPORTED_COMPARISONS


def uncomment(line):
  if line.startswith('#'):
    return line[1:]
  if line.startswith('//'):
    return line[2:]
  return line


def download_pypi_db():
  urllib.request.urlretrieve('https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip', 'pypi-db.zip')


def extract_packages_with_versions(osvs):
  dict = {}

  for osv in osvs:
    for affected in osv['affected']:
      if 'package' not in affected or affected['package']['ecosystem'] != 'PyPI':
        continue

      package = affected['package']['name']

      if package not in dict:
        dict[package] = []

      for version in affected.get('versions', []):
        try:
          dict[package].append(packaging.version.parse(version))
        except packaging.version.InvalidVersion:
          print(f'skipping invalid version {version} for {package}')

  # deduplicate and sort the versions for each package
  for package in dict:
    dict[package] = sorted(list(dict.fromkeys(dict[package])))

  return dict


def compare(v1, relate, v2):
  ops = {'<': operator.lt, '=': operator.eq, '>': operator.gt}
  return ops[relate](v1, v2)


def compare_versions(lines, select='all'):
  has_any_failed = False

  for line in lines:
    line = line.strip()

    if line == '' or line.startswith('#') or line.startswith('//'):
      maybe_unsupported = uncomment(line).strip()

      if is_unsupported_comparison(maybe_unsupported):
        print(f'\033[96mS\033[0m: \033[93m{maybe_unsupported}\033[0m')
      continue

    v1, op, v2 = line.strip().split(' ')

    r = compare(packaging.version.parse(v1), op, packaging.version.parse(v2))

    if not r:
      has_any_failed = True

    if select == 'failures' and r:
      continue

    if select == 'successes' and not r:
      continue

    color = '\033[92m' if r else '\033[91m'
    rs = 'T' if r else 'F'
    print(f'{color}{rs}\033[0m: \033[93m{line}\033[0m')
  return has_any_failed


def compare_versions_in_file(filepath, select='all'):
  with open(filepath) as f:
    lines = f.readlines()
    return compare_versions(lines, select)


def generate_version_compares(versions):
  comparisons = []
  for i, version in enumerate(versions):
    if i == 0:
      continue

    comparison = f'{versions[i - 1]} < {version}\n'

    if is_unsupported_comparison(comparison.strip()):
      comparison = '# ' + comparison
    comparisons.append(comparison)
  return comparisons


def generate_package_compares(packages):
  comparisons = []
  for package in packages:
    versions = packages[package]
    comparisons.extend(generate_version_compares(versions))

  # return comparisons
  return list(dict.fromkeys(comparisons))


def fetch_packages_versions():
  download_pypi_db()
  osvs = []

  with zipfile.ZipFile('pypi-db.zip') as db:
    for fname in db.namelist():
      with db.open(fname) as osv:
        osvs.append(json.loads(osv.read().decode('utf-8')))

  return extract_packages_with_versions(osvs)


outfile = 'internal/semantic/fixtures/pypi-versions-generated.txt'

packs = fetch_packages_versions()
with open(outfile, 'w') as f:
  f.writelines(generate_package_compares(packs))
  f.write('\n')

# set this to either "failures" or "successes" to only have those comparison results
# printed; setting it to anything else will have all comparison results printed
show = os.environ.get('VERSION_GENERATOR_PRINT', 'failures')

did_any_fail = compare_versions_in_file(outfile, show)

if did_any_fail:
  sys.exit(1)
