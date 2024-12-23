#!/usr/bin/env python3

import json
import operator
import os
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

# this requires being run on an OS that has a version of "rpm" installed which
# supports evaluating Lua expressions (most versions do); also make sure to consider
# the version of rpm being used in case there are changes to the comparing logic
# (last run with 1.19.7).
#
# note that both alpine and debian have a "rpm" package that supports this, which
# can be installed using "apk add rpm" and "apt install rpm" respectively.
#
# also note that because of the large amount of versions being used there is
# significant overhead in having to use a subprocess, so this generator caches
# the results of said subprocess calls; a typical no-cache run takes about 5+
# minutes whereas with the cache it only takes seconds.

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
  if line.startswith("#"):
    return line[1:]
  if line.startswith("//"):
    return line[2:]
  return line


def download_redhat_db():
  urllib.request.urlretrieve("https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/all.zip", "redhat-db.zip")


def extract_packages_with_versions(osvs):
  dict = {}

  for osv in osvs:
    for affected in osv['affected']:
      if 'package' not in affected or not affected['package']['ecosystem'].startswith('Red Hat'):
        continue

      package = affected['package']['name']

      if package not in dict:
        dict[package] = []

      for version in affected.get('versions', []):
        dict[package].append(RedHatVersion(version))

      for rang in affected.get('ranges', []):
        for event in rang['events']:
          if 'introduced' in event and event['introduced'] != '0':
            dict[package].append(RedHatVersion(event['introduced']))
          if 'fixed' in event:
            dict[package].append(RedHatVersion(event['fixed']))

  # deduplicate and sort the versions for each package
  for package in dict:
    dict[package] = sorted(list(dict.fromkeys(dict[package])))

  return dict


class RedHatVersionComparer:
  def __init__(self, cache_path):
    self.cache_path = Path(cache_path)
    self.cache = {}

    self._load_cache()

  def _load_cache(self):
    if self.cache_path:
      self.cache_path.touch()
      with open(self.cache_path, "r") as f:
        lines = f.readlines()

        for line in lines:
          line = line.strip()
          key, result = line.split(",")

          if result == "True":
            self.cache[key] = True
            continue
          if result == "False":
            self.cache[key] = False
            continue

          print(f"ignoring invalid cache entry '{line}'")

  def _save_to_cache(self, key, result):
    self.cache[key] = result
    if self.cache_path:
      self.cache_path.touch()
      with open(self.cache_path, "a") as f:
        f.write(f"{key},{result}\n")

  def _compare1(self, a, op, b):
    cmd = ["rpm", "--eval", f"%{{lua:print(rpm.vercmp('{a}', '{b}'))}}"]
    out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if out.returncode != 0 or out.stderr:
      raise Exception(f"rpm did not like comparing {a} {op} {b}: {out.stderr.decode('utf-8')}")

    r = out.stdout.decode('utf-8').strip()

    if r == "0" and op == "=":
      return True
    elif r == "1" and op == ">":
      return True
    elif r == "-1" and op == "<":
      return True

    return False

  def _compare2(self, a, op, b):
    if op == "=":
      op = "=="  # lua uses == for equality

    cmd = ["rpm", "--eval", f"%{{lua:print(rpm.ver('{a}') {op} rpm.ver('{b}'))}}"]
    out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if out.returncode != 0 or out.stderr:
      raise Exception(f"rpm did not like comparing {a} {op} {b}: {out.stderr.decode('utf-8')}")

    r = out.stdout.decode('utf-8').strip()

    if r == "true":
      return True
    elif r == "false":
      return False

    raise Exception(f"unexpected result from rpm: {r}")


  def compare(self, a, op, b):
    key = f"{a} {op} {b}"
    if key in self.cache:
      return self.cache[key]

    r = self._compare1(a, op, b)
    # r = self._compare2(a, op, b)

    self._save_to_cache(key, r)
    return r


redhat_comparer = RedHatVersionComparer("/tmp/redhat-versions-generator-cache.csv")


class RedHatVersion:
  def __str__(self):
    return self.version

  def __hash__(self):
    return hash(self.version)

  def __init__(self, version):
    self.version = version

  def __lt__(self, other):
    return redhat_comparer.compare(self.version, '<', other.version)

  def __gt__(self, other):
    return redhat_comparer.compare(self.version, '>', other.version)

  def __eq__(self, other):
    return redhat_comparer.compare(self.version, '=', other.version)


def compare(v1, relate, v2):
  ops = {'<': operator.lt, '=': operator.eq, '>': operator.gt}
  return ops[relate](v1, v2)


def compare_versions(lines, select="all"):
  has_any_failed = False

  for line in lines:
    line = line.strip()

    if line == "" or line.startswith('#') or line.startswith('//'):
      maybe_unsupported = uncomment(line).strip()

      if is_unsupported_comparison(maybe_unsupported):
        print(f"\033[96mS\033[0m: \033[93m{maybe_unsupported}\033[0m")
      continue

    v1, op, v2 = line.strip().split(" ")

    r = compare(RedHatVersion(v1), op, RedHatVersion(v2))

    if not r:
      has_any_failed = r

    if select == "failures" and r:
      continue

    if select == "successes" and not r:
      continue

    color = '\033[92m' if r else '\033[91m'
    rs = "T" if r else "F"
    print(f"{color}{rs}\033[0m: \033[93m{line}\033[0m")
  return has_any_failed


def compare_versions_in_file(filepath, select="all"):
  with open(filepath) as f:
    lines = f.readlines()
    return compare_versions(lines, select)


def generate_version_compares(versions):
  comparisons = []
  for i, version in enumerate(versions):
    if i == 0:
      continue

    comparison = f"{versions[i - 1]} < {version}\n"

    if is_unsupported_comparison(comparison.strip()):
      comparison = "# " + comparison
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
  download_redhat_db()
  osvs = []

  with zipfile.ZipFile('redhat-db.zip') as db:
    for fname in db.namelist():
      with db.open(fname) as osv:
        osvs.append(json.loads(osv.read().decode('utf-8')))

  return extract_packages_with_versions(osvs)


outfile = "internal/semantic/fixtures/redhat-versions-generated.txt"

packs = fetch_packages_versions()
with open(outfile, "w") as f:
  f.writelines(generate_package_compares(packs))
  f.write("\n")

# set this to either "failures" or "successes" to only have those comparison results
# printed; setting it to anything else will have all comparison results printed
show = os.environ.get("VERSION_GENERATOR_PRINT", "failures")

did_any_fail = compare_versions_in_file(outfile, show)

if did_any_fail:
  sys.exit(1)
