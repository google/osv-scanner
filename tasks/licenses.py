"""
Utility functions for manipulating licenses
"""

import json
import os
import re
import shutil
import tempfile

import yaml
from invoke.exceptions import Exit

# Files searched for COPYRIGHT_RE
COPYRIGHT_LOCATIONS = [
    'license',
    'LICENSE',
    'license.md',
    'LICENSE.md',
    'LICENSE.txt',
    'License.txt',
    'license.txt',
    'COPYING',
    'NOTICE',
    'README',
    'README.md',
    'README.mdown',
    'README.markdown',
    'COPYRIGHT',
    'COPYRIGHT.txt',
]

AUTHORS_LOCATIONS = [
    'AUTHORS',
    'AUTHORS.md',
    'CONTRIBUTORS',
]

# General match for anything that looks like a copyright declaration
COPYRIGHT_RE = re.compile(r'copyright\s+(?:©|\(c\)\s+)?(?:(?:[0-9 ,-]|present)+\s+)?(?:by\s+)?(.*)', re.I)

# Copyright strings to ignore, as they are not owners.  Most of these are from
# boilerplate license files.
#
# These match at the beginning of the copyright (the result of COPYRIGHT_RE).
COPYRIGHT_IGNORE_RES = [
    re.compile(r'copyright(:? and license)?$', re.I),
    re.compile(r'copyright (:?holder|owner|notice|license|statement)', re.I),
    re.compile(r'Copyright & License -'),
    re.compile(r'copyright .yyyy. .name of copyright owner.', re.I),
    re.compile(r'copyright .yyyy. .name of copyright owner.', re.I),
]

# Match for various suffixes that need not be included
STRIP_SUFFIXES_RE = []

# Packages containing CONTRIBUTORS files that do not use #-style comments
# in their header; we skip until the first blank line.
CONTRIBUTORS_WITH_UNCOMMENTED_HEADER = [
    'github.com/patrickmn/go-cache',
    'gopkg.in/Knetic/govaluate.v3',
]


# FIXME: This doesn't include licenses for non-go dependencies, like the javascript libs we use for the web gui
def get_licenses_list(ctx):
    # we need the full vendor tree in order to perform this analysis
    from .go import deps_vendored

    deps_vendored(ctx)

    try:
        licenses = wwhrd_licenses(ctx)
        licenses = find_copyright(ctx, licenses)
        return licenses_csv(licenses)
    finally:
        shutil.rmtree("vendor/")


def is_valid_quote(copyright):
    stack = []
    quotes_to_check = ["'", '"']
    for c in copyright:
        if c in quotes_to_check:
            if stack and stack[-1] == c:
                stack.pop()
            else:
                stack.append(c)
    return len(stack) == 0


def licenses_csv(licenses):
    licenses.sort(key=lambda lic: lic["package"])

    def fmt_copyright(lic):
        # discards copyright with invalid quotes to ensure generated csv is valid
        filtered_copyright = []
        for copyright in lic["copyright"]:
            if is_valid_quote(copyright):
                filtered_copyright.append(copyright)
            else:
                print(
                    f'The copyright `{copyright}` of `{lic["component"]},{lic["package"]}` was discarded because its copyright contains invalid quotes. To fix the discarded copyright, modify `.copyright-overrides.yml` to fix the bad-quotes copyright'
                )
        if len(copyright) == 0:
            copyright = "UNKNOWN"
        copyright = ' | '.join(sorted(filtered_copyright))
        # quote for inclusion in CSV, if necessary
        if ',' in copyright:
            copyright = copyright.replace('"', '""')
            copyright = f'"{copyright}"'
        return copyright

    return [f"{l['component']},{l['package']},{l['license']},{fmt_copyright(l)}" for l in licenses]


def wwhrd_licenses(ctx):
    # local imports
    from urllib.parse import urlparse

    import requests
    from requests.exceptions import RequestException

    # Read the list of packages to exclude from the list from wwhrd's
    exceptions_wildcard = []
    exceptions = []
    additional = {}
    overrides = {}
    with open('.wwhrd.yml', encoding="utf-8") as wwhrd_conf_yml:
        wwhrd_conf = yaml.safe_load(wwhrd_conf_yml)
        for pkg in wwhrd_conf['exceptions']:
            if pkg.endswith("/..."):
                # TODO(python3.9): use removesuffix
                exceptions_wildcard.append(pkg[: -len("/...")])
            else:
                exceptions.append(pkg)

        for pkg, license in wwhrd_conf.get('additional', {}).items():
            additional[pkg] = license

        for pkg, lic in wwhrd_conf.get('overrides', {}).items():
            overrides[pkg] = lic

    def is_excluded(pkg):
        if pkg in exceptions:
            return True
        for exception in exceptions_wildcard:
            if pkg.startswith(exception):
                return True
        return False

    # Parse the output of wwhrd to generate the list
    result = ctx.run('wwhrd list --no-color', hide='err')
    licenses = []
    if result.stderr:
        for line in result.stderr.split("\n"):
            index = line.find('msg="Found License"')
            if index == -1:
                continue
            license = ""
            package = ""
            for val in line[index + len('msg="Found License"') :].split(" "):
                if val.startswith('license='):
                    license = val[len('license=') :]
                elif val.startswith('package='):
                    package = val[len('package=') :]
                    if is_excluded(package):
                        print(f"Skipping {package} ({license}) excluded in .wwhrd.yml")
                    else:
                        if package in overrides:
                            license = overrides[package]
                        licenses.append({"component": "core", "package": package, "license": license})

    for pkg, lic in additional.items():
        url = urlparse(lic)
        url = url._replace(scheme='https', netloc=url.path, path='')
        try:
            resp = requests.get(url.geturl())
            resp.raise_for_status()

            with tempfile.TemporaryDirectory() as tempdir:
                with open(os.path.join(tempdir, 'LICENSE'), 'w', encoding="utf-8") as lfp:
                    lfp.write(resp.text)
                    lfp.flush()

                    temp_path = os.path.dirname(lfp.name)
                    result = ctx.run(f"license-detector -f json {temp_path}", hide="out")
                    if result.stdout:
                        results = json.loads(result.stdout)
                        for project in results:
                            if 'error' in project:
                                continue

                            # we get the first match
                            license = project['matches'][0]['license']
                        licenses.append({"component": "core", "package": pkg, "license": license})
        except RequestException:
            print(f"There was an issue reaching license {pkg} for pkg {lic}")
            raise Exit(code=1)

    return licenses


def find_copyright_for(package, overrides, ctx):
    copyright = []

    over = overrides(package)
    if over:
        return over

    # since this is a package path, copyright information for the go module may
    # be in a parent directory.
    if package.count('/') > 0:
        parent = find_copyright_for('/'.join(package.split('/')[:-1]), overrides, ctx)
    else:
        parent = []

    # search the package dir for a bunch of heuristically-useful files that might
    # contain copyright or authorship information
    pkgdir = os.path.join('vendor', package)

    for filename in COPYRIGHT_LOCATIONS:
        filename = os.path.join(pkgdir, filename)
        if os.path.isfile(filename):
            for line in open(filename, encoding="utf-8"):
                mo = COPYRIGHT_RE.search(line)
                if not mo:
                    continue
                cpy = mo.group(0)

                # ignore a few spurious matches from license boilerplate
                if any(ign.match(cpy) for ign in COPYRIGHT_IGNORE_RES):
                    continue

                # strip some suffixes
                for suff_re in STRIP_SUFFIXES_RE:
                    cpy = suff_re.sub('', cpy)

                cpy = cpy.strip().rstrip('.')
                if cpy:
                    copyright.append(cpy)

    # skip through the first blank line of a file
    def skipheader(lines):
        for line in lines:
            if not line.strip():
                break
        for line in lines:
            yield line

    for filename in AUTHORS_LOCATIONS:
        filename = os.path.join(pkgdir, filename)
        if os.path.exists(filename):
            lines = open(filename, encoding="utf-8")
            if package in CONTRIBUTORS_WITH_UNCOMMENTED_HEADER:
                lines = skipheader(lines)
            for line in lines:
                line = line.strip()
                if not line or line[0] == '#':
                    continue
                copyright.append(line)

    return list(set(parent + copyright))


def read_overrides():
    with open('.copyright-overrides.yml', encoding='utf-8') as overrides_yml:
        override_spec = yaml.safe_load(overrides_yml)
    override_pats = []
    for pkg, dpy in override_spec.items():
        # cast dpy to a list
        if not isinstance(dpy, list):
            dpy = [dpy]
            override_spec[pkg] = dpy

        if pkg.endswith('*'):
            pkg = pkg[:-1]
            override_pats.append((pkg, dpy))

    def overrides(pkg):
        try:
            return override_spec[pkg]
        except KeyError:
            pass

        for pat, dpy in override_pats:
            if pkg.startswith(pat):
                return dpy

    return overrides


def find_copyright(ctx, licenses):
    overrides = read_overrides()
    for lic in licenses:
        pkg = lic['package']
        cpy = find_copyright_for(pkg, overrides, ctx)
        if cpy:
            lic['copyright'] = cpy
        else:
            lic['copyright'] = ['UNKNOWN']

    return licenses
