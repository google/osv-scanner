#!/usr/bin/env python3
"""Automated guided remediation workflow for `osv-scanner fix`."""

import os.path
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple


PATCH_STRATEGIES = [
    ['--strategy=in-place'],  # Try transitive dependency upgrades without relocking.
    ['--strategy=relock'],  # Relock the manifest and try direct dependency bumps.
    # Additional filters can narrow scope, for example:
    # ['--strategy=relock', '--upgrade-config=minor', '--max-depth=5'].
]


@dataclass
class FixContext:
    """Shared configuration for executing `osv-scanner fix`."""

    directory: str
    manifest: str
    lockfile: str
    osv_fix_args: List[str]


def run_fix(
    context: FixContext,
    n_patches: int,
    avoid_pkgs: Sequence[str],
    strategy: Sequence[str],
) -> Tuple[List[str], Optional[int], Optional[int]]:
    """Apply `osv-scanner fix` and return upgrade details."""

    subprocess.check_call(
        ['git', 'checkout', 'package.json', 'package-lock.json'],
        cwd=context.directory,
    )

    cmd = [
        'osv-scanner',
        'fix',
        '-M',
        context.manifest,
        '-L',
        context.lockfile,
        *context.osv_fix_args,
        *strategy,
    ]

    if n_patches != 0:
        cmd.extend(['--apply-top', str(n_patches)])

    for pkg in avoid_pkgs:
        cmd.extend(['--upgrade-config', f'{pkg}:none'])

    try:
        output = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError as error:
        output = (error.stdout or '') + (error.stderr or '')

    upgraded = [
        match[1]
        for match in re.finditer(r'UPGRADED-PACKAGE: (.*),(.*),(.*)', output)
    ]
    remaining_vulns: Optional[int] = None
    unfixable_vulns: Optional[int] = None

    match = re.search(r'REMAINING-VULNS:\s*(\d+)', output)
    if match:
        remaining_vulns = int(match.group(1))

    match = re.search(r'UNFIXABLE-VULNS:\s*(\d+)', output)
    if match:
        unfixable_vulns = int(match.group(1))

    return upgraded, remaining_vulns, unfixable_vulns


def run_loop(
    context: FixContext,
    strategy: Sequence[str],
) -> Tuple[List[str], Optional[int], Optional[int], List[str]]:
    """Iteratively apply a strategy until tests pass or patches are exhausted."""

    valid: List[str] = []
    avoid: List[str] = []
    n_patches = 0

    print('===== Attempting auto-patch with strategy', strategy, '=====')

    remaining: Optional[int] = None
    total_unfixable: Optional[int] = None

    while True:
        changes, remaining, unfixable = run_fix(context, n_patches, avoid, strategy)
        if changes == valid:
            break

        print('===== Trying to upgrade:', changes, '=====')
        print('===== Current blocklist:', avoid, '=====')

        install_result = subprocess.call(['npm', 'ci'], cwd=context.directory)
        test_result = subprocess.call(['npm', 'run', 'test'], cwd=context.directory)

        if install_result or test_result:
            if n_patches == 0:
                total_unfixable = unfixable
                n_patches += 1
                continue

            print('===== Tests failed, blocklisting upgrades =====')

            for change in changes:
                if change not in valid:
                    avoid.append(change)
            print('===== Current blocklist:', avoid, '=====')
        else:
            if n_patches == 0:
                valid = changes
                break

            valid = changes
            n_patches += 1

    if valid:
        print()
        print('===== The following packages have been changed and verified =====')
        print('===== against the tests: =====')
        for package in valid:
            print(package)

    return valid, remaining, total_unfixable, avoid


def is_git_repo(directory: str) -> bool:
    """Return True when the directory resides in a Git repository."""

    try:
        subprocess.check_call(
            ['git', '-C', directory, 'rev-parse'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return False
    return True


def main(argv: List[str]) -> int:
    """Entry point for the guided remediation helper script."""

    if not argv:
        print(f'Usage: {sys.argv[0]} <project-directory> [osv-scanner args...]')
        return 1

    directory, *osv_fix_args = argv

    if not is_git_repo(directory):
        print(f'{directory} is not part of a git repository')
        return 1

    context = FixContext(
        directory=directory,
        manifest=os.path.join(directory, 'package.json'),
        lockfile=os.path.join(directory, 'package-lock.json'),
        osv_fix_args=osv_fix_args,
    )

    best_strategy: Optional[Sequence[str]] = None
    best_changes: List[str] = []
    best_avoid: List[str] = []
    best_remaining_value = float('inf')
    best_remaining: Optional[int] = None
    best_unfixable: Optional[int] = None

    for strategy in PATCH_STRATEGIES:
        changes, remaining, unfixable, avoid = run_loop(context, strategy)
        if not changes:
            continue

        remaining_value = float(remaining) if remaining is not None else float('inf')
        if remaining_value < best_remaining_value:
            best_strategy = strategy
            best_changes = changes
            best_avoid = avoid
            best_remaining_value = remaining_value
            best_remaining = remaining
            best_unfixable = unfixable

    if best_strategy is None:
        print('No strategy produced a successful patch set.')
        return 1

    print()
    print('===== Auto-patch completed with the following changed packages =====')
    print('Best strategy:', best_strategy)
    for package in best_changes:
        print(package)

    if best_avoid:
        print('The following packages cannot be upgraded due to failing tests:')
        for package in best_avoid:
            print(package)
    else:
        print('All attempted package upgrades passed tests.')

    print()
    if best_remaining is not None:
        print(best_remaining, 'vulnerabilities remain')
    else:
        print('The remaining vulnerability count is unavailable.')

    if best_unfixable is not None:
        print(
            best_unfixable,
            'vulnerabilities are impossible to fix by package upgrades',
        )

    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
