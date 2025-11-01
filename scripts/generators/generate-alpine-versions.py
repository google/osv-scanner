#!/usr/bin/env python3
"""Generate Alpine version comparison fixtures using Docker and apk."""

import atexit
import json
import operator
import os
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional


# This script requires Docker with access to an Alpine image. A background
# container is started on demand so that repeated apk invocations are fast.
#
# Results are cached under `/tmp` to avoid repeating expensive comparisons.


UNSUPPORTED_COMPARISONS: List[str] = []
CACHE_FILE = Path('/tmp/alpine-versions-generator-cache.csv')
OUTPUT_FILE = Path('internal/semantic/testdata/alpine-versions-generated.txt')
ALPINE_VERSION = '3.10'
DEFAULT_COMPARE_METHOD = 'exec'


def is_unsupported_comparison(line: str) -> bool:
    """Return True when a comparison is explicitly unsupported."""

    return line in UNSUPPORTED_COMPARISONS


def uncomment(line: str) -> str:
    """Remove leading comment prefixes from a line."""

    if line.startswith('#'):
        return line[1:]
    if line.startswith('//'):
        return line[2:]
    return line


def download_alpine_db(destination: Path) -> None:
    """Download the Alpine OSV database to the given destination path."""

    urllib.request.urlretrieve(
        'https://osv-vulnerabilities.storage.googleapis.com/Alpine/all.zip',
        str(destination),
    )


def extract_packages_with_versions(
    osvs: Iterable[dict],
) -> Dict[str, List['AlpineVersion']]:
    """Return mapping of package -> sorted unique AlpineVersion instances."""

    packages: Dict[str, List['AlpineVersion']] = {}

    for osv in osvs:
        for affected in osv.get('affected', []):
            package_info = affected.get('package')
            if not package_info:
                continue

            ecosystem = package_info.get('ecosystem', '')
            if not ecosystem.startswith('Alpine'):
                continue

            package_name = package_info.get('name')
            if not package_name:
                continue

            packages.setdefault(package_name, [])

            for version in affected.get('versions', []):
                packages[package_name].append(AlpineVersion(version))

    for package_name, versions in packages.items():
        deduplicated = list(dict.fromkeys(versions))
        packages[package_name] = sorted(deduplicated)

    return packages


class AlpineVersionComparer:
    """Compare Alpine package versions via apk command execution."""

    def __init__(self, cache_path: Path, compare_method: str) -> None:
        self.cache_path = cache_path
        self.cache: Dict[str, bool] = {}
        self._compare_method = compare_method
        self._docker_container: Optional[str] = None
        self._load_cache()

    def _start_docker_container(self) -> None:
        """Ensure a reusable Alpine container is running."""

        if self._docker_container is not None:
            return

        container_name = f'alpine-{ALPINE_VERSION}-container'
        cmd = [
            'docker',
            'run',
            '--rm',
            '--name',
            container_name,
            '-d',
            f'alpine:{ALPINE_VERSION}',
            'tail',
            '-f',
            '/dev/null',
        ]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode('utf-8')
            raise RuntimeError(
                f'failed to start {container_name} container: {stderr}',
            )

        self._docker_container = container_name
        atexit.register(self._stop_docker_container)

    def _stop_docker_container(self) -> None:
        """Stop the background Alpine container if one was started."""

        if self._docker_container is None:
            return

        cmd = ['docker', 'stop', '-t', '0', self._docker_container]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode('utf-8')
            raise RuntimeError(
                f'failed to stop {self._docker_container} container: {stderr}',
            )

        self._docker_container = None

    def _load_cache(self) -> None:
        """Populate in-memory cache from the on-disk cache file."""

        if not self.cache_path:
            return

        self.cache_path.touch()
        with self.cache_path.open('r', encoding='utf-8') as cache_file:
            for line in cache_file:
                line = line.strip()
                if not line:
                    continue

                try:
                    key, result = line.split(',', maxsplit=1)
                except ValueError:
                    print(f"Ignoring invalid cache entry '{line}'")
                    continue

                if result == 'True':
                    self.cache[key] = True
                elif result == 'False':
                    self.cache[key] = False
                else:
                    print(f"Ignoring invalid cache entry '{line}'")

    def _save_to_cache(self, key: str, result: bool) -> None:
        """Persist a comparison result to disk."""

        self.cache[key] = result
        if not self.cache_path:
            return

        self.cache_path.touch()
        with self.cache_path.open('a', encoding='utf-8') as cache_file:
            cache_file.write(f'{key},{result}\n')

    def _compare_command(self, version_a: str, version_b: str) -> List[str]:
        if self._compare_method == 'run':
            return [
                'docker',
                'run',
                '--rm',
                f'alpine:{ALPINE_VERSION}',
                'apk',
                'version',
                '-t',
                version_a,
                version_b,
            ]

        self._start_docker_container()
        if self._docker_container is None:
            raise RuntimeError('docker container was not started successfully')

        return [
            'docker',
            'exec',
            self._docker_container,
            'apk',
            'version',
            '-t',
            version_a,
            version_b,
        ]

    def compare(self, version_a: str, relation: str, version_b: str) -> bool:
        """Compare two versions using apk and cache the result."""

        key = f'{version_a} {relation} {version_b}'
        if key in self.cache:
            return self.cache[key]

        cmd = self._compare_command(version_a, version_b)
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode('utf-8')
            raise RuntimeError(
                f'apk failed to compare {version_a} {relation} {version_b}: {stderr}',
            )

        comparison = result.stdout.decode('utf-8').strip() == relation
        self._save_to_cache(key, comparison)
        return comparison


ALPINE_COMPARER = AlpineVersionComparer(CACHE_FILE, DEFAULT_COMPARE_METHOD)


class AlpineVersion:
    """Wrapper around an Alpine version string with apk comparisons."""

    def __init__(self, version: str) -> None:
        self.version = version

    def __str__(self) -> str:
        return self.version

    def __hash__(self) -> int:
        return hash(self.version)

    def __lt__(self, other: 'AlpineVersion') -> bool:
        return ALPINE_COMPARER.compare(self.version, '<', other.version)

    def __gt__(self, other: 'AlpineVersion') -> bool:
        return ALPINE_COMPARER.compare(self.version, '>', other.version)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AlpineVersion):
            return NotImplemented
        return ALPINE_COMPARER.compare(self.version, '=', other.version)


def compare_versions_once(
    version_a: AlpineVersion,
    relation: str,
    version_b: AlpineVersion,
) -> bool:
    """Compare two AlpineVersion instances using rich comparisons."""

    operations = {'<': operator.lt, '=': operator.eq, '>': operator.gt}
    return operations[relation](version_a, version_b)


def compare_versions(lines: Iterable[str], selection: str = 'all') -> bool:
    """Print comparison results for the provided lines."""

    has_any_failed = False

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            maybe_unsupported = uncomment(line).strip()
            if is_unsupported_comparison(maybe_unsupported):
                print(f'\033[96mS\033[0m: \033[93m{maybe_unsupported}\033[0m')
            continue

        version_a, relation, version_b = line.split(' ')
        result = compare_versions_once(
            AlpineVersion(version_a),
            relation,
            AlpineVersion(version_b),
        )

        if not result:
            has_any_failed = True

        if selection == 'failures' and result:
            continue
        if selection == 'successes' and not result:
            continue

        color = '\033[92m' if result else '\033[91m'
        outcome = 'T' if result else 'F'
        print(f'{color}{outcome}\033[0m: \033[93m{line}\033[0m')

    return has_any_failed


def compare_versions_in_file(filepath: Path, selection: str = 'all') -> bool:
    """Load comparison data from a file and process it."""

    with filepath.open(encoding='utf-8') as compare_file:
        return compare_versions(compare_file, selection)


def generate_version_compares(versions: List[AlpineVersion]) -> List[str]:
    """Generate sequential comparison lines for the provided versions."""

    comparisons: List[str] = []
    for index, version in enumerate(versions):
        if index == 0:
            continue

        comparison = f'{versions[index - 1]} < {version}\n'
        if is_unsupported_comparison(comparison.strip()):
            comparison = '# ' + comparison
        comparisons.append(comparison)

    return comparisons


def generate_package_compares(
    packages: Dict[str, List[AlpineVersion]],
) -> List[str]:
    """Create all comparison lines for each package in the mapping."""

    comparisons: List[str] = []
    for versions in packages.values():
        comparisons.extend(generate_version_compares(versions))

    # Deduplicate while preserving order.
    return list(dict.fromkeys(comparisons))


def fetch_packages_versions() -> Dict[str, List[AlpineVersion]]:
    """Download and parse the Alpine vulnerability database."""

    archive_path = Path('alpine-db.zip')
    download_alpine_db(archive_path)
    osvs: List[dict] = []

    with zipfile.ZipFile(archive_path) as archive:
        for filename in archive.namelist():
            with archive.open(filename) as osv_file:
                data = osv_file.read().decode('utf-8')
                osvs.append(json.loads(data))

    return extract_packages_with_versions(osvs)


def main() -> int:
    """Generate the fixture file and report comparison discrepancies."""

    packages = fetch_packages_versions()

    with OUTPUT_FILE.open('w', encoding='utf-8') as outfile:
        outfile.writelines(generate_package_compares(packages))
        outfile.write('\n')

    selection = os.environ.get('VERSION_GENERATOR_PRINT', 'failures')
    did_any_fail = compare_versions_in_file(OUTPUT_FILE, selection)

    return 1 if did_any_fail else 0


if __name__ == '__main__':
    sys.exit(main())
