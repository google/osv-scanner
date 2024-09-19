#!/usr/bin/env python3
"""
Proof of concept demonstrating an automated guided remediation patching workflow.
We progressively try more and more patches until tests fail.
Requires osv-scanner to be in your PATH.
"""

import os.path
import re
import subprocess
import sys
from typing import List, Tuple

PATCH_STRATEGIES = [
    ['--strategy=in-place'],  # Try every single transitive dependency upgrade without relocking or bumping direct dependencies.json.
    ['--strategy=relock'],  # Relock the manifest and try direct dependency bumps.
    # This could also include things like:
    # '--min-severity=X'  Minimum severity of vulnerabilities to consider.
    # '--max-depth=Y': Maximum (shortest) dependency depth
    # '--upgrade-config={major/minor/patch}':  What level of package upgrades are allowed.
    # etc... which can help reduce/increase the scope of changes by prioritizing vulnerabilities according to these filters.
    # e.g. ['--strategy=relock', '--upgrade-config=minor', '--max-depth=5'],  # Relock the manifest and try direct dependency bumps.
    # See `osv-scanner fix --help`.
]

if len(sys.argv) < 2:
  print(f'Usage: {sys.argv[0]} <project-directory>')
  sys.exit(1)

directory = sys.argv[1]
osv_fix_args = sys.argv[2:]

# check if the directory is within a git repo
if subprocess.call(['git', '-C', directory, 'rev-parse']):
  print(f'{directory} is not part of a git repository')
  sys.exit(1)

manifest = os.path.join(directory, 'package.json')
lockfile = os.path.join(directory, 'package-lock.json')


def run_fix(n_patches: int, avoid_pkgs: List[str], strategy: List[str]) -> Tuple[List[str], int, int]:
  # restore package.json & package-lock.json
  subprocess.check_call(['git', 'checkout', 'package.json', 'package-lock.json'], cwd=directory)
  # run osv-fix and parse changes
  cmd = ['osv-scanner', 'fix', '--non-interactive', '-M', manifest, '-L', lockfile] + osv_fix_args + strategy

  # 0 is a magic value that means we try all patches.
  if n_patches != 0:
    cmd.extend(['--apply-top', str(n_patches)])

  for pkg in avoid_pkgs:
    cmd.extend(['--upgrade-config', f'{pkg}:none'])

  try:
    output = subprocess.check_output(cmd, text=True)
  except subprocess.CalledProcessError as e:
    output = (e.stdout or '') + (e.stderr or '')

  upgraded = [m[1] for m in re.finditer(r'UPGRADED-PACKAGE: (.*),(.*),(.*)', output)]
  remaining_vulns = None
  unfixable_vulns = None

  match = re.search(r'REMAINING-VULNS:\s*(\d+)', output)
  if match:
    remaining_vulns = int(match.group(1))

  match = re.search(r'UNFIXABLE-VULNS:\s*(\d+)', output)
  if match:
    unfixable_vulns = int(match.group(1))

  return upgraded, remaining_vulns, unfixable_vulns


def run_loop(strategy: List[str]) -> Tuple[List[str], int, int, List[str]]:
  valid = []
  avoid = []
  # 0 is a special value meaning that we try applying every patch. This is
  # meant as a shortcut in case this would've succeeded anyway.
  n_patches = 0

  print('===== Attempting auto-patch with strategy', strategy, '=====')

  remaining = None
  total_unfixable = None

  while True:
    changes, remaining, unfixable = run_fix(n_patches, avoid, strategy)
    if changes == valid:
      # if the result of running osv-fix hasn't changed, then we've run out of patches to apply
      break

    print('===== Trying to upgrade:', changes, '=====')
    print('===== Current blocklist:', avoid, '=====')
    # check the install & tests
    if subprocess.call(['npm', 'ci'], cwd=directory) or subprocess.call(['npm', 'run', 'test'], cwd=directory):  # tests failed
      if n_patches == 0:
        # First try with every single patch.
        # Record the unfixable count using this, as it represents the real
        # unfixable count if every possible package upgrade was allowed.
        total_unfixable = unfixable
        n_patches += 1
        continue

      print('===== Tests failed, blocklisting upgrades =====')
      # add each new package to the avoid list

      for c in changes:
        if c not in valid:
          avoid.append(c)
      print('===== Current blocklist:', avoid, '=====')
    else:  # tests passed
      if n_patches == 0:
        valid = changes
        break

      # try now with the next patch
      valid = changes
      n_patches += 1

  if valid:
    print()
    print('===== The following packages have been changed and verified against the tests: =====')
    for v in valid:
      print(v)

  return valid, remaining, total_unfixable, avoid


best_strategy = None
best_changes = []
best_avoid = []
best_remaining = 10000000
best_unfixable = None

for strategy in PATCH_STRATEGIES:
  changes, remaining, unfixable, avoid = run_loop(strategy)
  if changes and remaining < best_remaining:
    best_strategy = strategy
    best_changes = changes
    best_avoid = avoid
    best_remaining = remaining
    best_unfixable = unfixable

print()
print('===== Auto-patch completed with the following changed packages =====')
print('Best strategy:', best_strategy)
for v in best_changes:
  print(v)

print('The follow packages cannot be upgraded due to failing tests:')
for v in best_avoid:
  print(v)

print()
print(best_remaining, 'vulnerabilities remain')

if best_unfixable:
  print(best_unfixable, 'vulnerabilities are impossible to fix by package upgrades')
