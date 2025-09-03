# Copyright 2022 OSV Schema Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Debian to OSV converter."""
import argparse
import collections
import io
import json
import os
import re
from datetime import datetime, timezone
import subprocess
import typing
from urllib3 import request
from enum import Enum

import dateutil.parser
import markdownify
#import pandas as pd

import osv
import osv.ecosystems

WEBWML_SECURITY_PATH = os.path.join('english', 'security')
WEBWML_LTS_SECURITY_PATH = os.path.join('english', 'lts', 'security')
SECURITY_TRACKER_DSA_PATH = os.path.join('data', 'DSA', 'list')
SECURITY_TRACKER_DTSA_PATH = os.path.join('data', 'DTSA', 'list')
SECURITY_TRACKER_DLA_PATH = os.path.join('data', 'DLA', 'list')
DEBIAN_BASE_URL = 'https://www.debian.org'

LEADING_WHITESPACE = re.compile(r'^\s')

# e.g. [25 Apr 2022] DSA-5124-1 ffmpeg - security update
DSA_PATTERN = re.compile(r'\[(.*?)]\s*([\w-]+)\s*(.*)')

# e.g. [buster] - xz-utils 5.2.4-1+deb10u1
VERSION_PATTERN = re.compile(r'\[(.*?)]\s*-\s*([^\s]+)\s*([^\s]+)')

# TODO: Alternative is to use a xml parser here,
#  though the data is not fully compliant with the xml standard
#  It is possible to parse with an html parser however

# e.g. <define-tag moreinfo>\n Some html here \n</define-tag>
WML_DESCRIPTION_PATTERN = re.compile(
    r'<define-tag moreinfo>((?:.|\n)*)</define-tag>', re.MULTILINE)

# e.g. <define-tag report_date>2022-1-04</define-tag>
WML_REPORT_DATE_PATTERN = re.compile(
    r'<define-tag report_date>(.*)</define-tag>')

# e.g. DSA-12345-2, -2 is the extension
DSA_OR_DLA_WITH_NO_EXT = re.compile(r'd[sl]a-\d+')

NOT_AFFECTED_VERSION = '<not-affected>'
UNFIXED_VERSION = '<unfixed>'
END_OF_LIFE_VERSION = '<end-of-life>'

# Prefix used to identify a new date line
GIT_DATE_PREFIX = '-----'


class AdvisoryType(Enum):
  DSA = 'DSA'
  DLA = 'DLA'
  DTSA = 'DTSA'

  def __str__(self):
    return self.value


class AffectedInfo:
  """Debian version info."""
  package: str
  ranges: [str]
  fixed: str
  versions: [str]
  debian_release_version: str

  def __init__(self, version: str, package: str, fixed: str):
    self.package = package
    self.fixed = fixed
    self.debian_release_version = version

  def to_dict(self):
    """Convert to dict for output"""
    result = {
        'package': {
            'ecosystem': 'Debian:' + self.debian_release_version,
            'name': self.package
        },
        'ranges': [{
            'type': 'ECOSYSTEM',
            'events': [{
                'introduced': '0'
            }]
        }],
    }

    if self.fixed:
      result['ranges'][0]['events'].append({'fixed': self.fixed})

    return result

  def __repr__(self):
    return json.dumps(self, default=dumper)


class Reference:
  """OSV reference format"""

  type: str
  url: str

  def __init__(self, url_type, url):
    self.type = url_type
    self.url = url


class AdvisoryInfo:
  """Debian advisory info."""

  id: str
  summary: str
  details: str
  published: str
  modified: str
  affected: list[AffectedInfo]
  aliases: list[str]
  related: list[str]
  upstream: list[str]
  references: list[Reference]

  def __init__(self, adv_id: str, summary: str, published: str):
    self.id = adv_id
    self.summary = summary
    self.affected = []
    self.aliases = []
    self.related = []
    self.upstream = []
    # Set a placeholder value for published and modified, if there is wml files
    # this will be replaced
    self.published = published
    self.modified = published
    self.details = ''
    self.references = []

  def to_dict(self):
    return self.__dict__

  def __repr__(self):
    return json.dumps(self, default=dumper)


Advisories = typing.Dict[str, AdvisoryInfo]
"""Type alias for collection of advisory info"""


def create_codename_to_version() -> typing.Dict[str, str]:
  """Returns the codename to version mapping"""
  with request.urlopen(
      'https://debian.pages.debian.net/distro-info-data/debian.csv') as csv:
    df = pd.read_csv(csv, dtype=str)
    # `series` appears to be `codename` but with all lowercase
    result = dict(zip(df['series'], df['version']))
    result['sid'] = 'unstable'
    return result


def dumper(obj):
  try:
    return obj.to_dict()
  except AttributeError:
    return obj.__dict__


def parse_security_tracker_file(advisories: Advisories,
                                security_tracker_repo: str,
                                security_tracker_path: str):
  """Parses the security tracker files into the advisories object"""

  codename_to_version = create_codename_to_version()

  with open(
      os.path.join(security_tracker_repo, security_tracker_path),
      encoding='utf-8') as file_handle:
    current_advisory = None

    # Enumerate advisories + version info from security-tracker.
    for line in file_handle:
      line = line.rstrip()
      if not line:
        continue

      if LEADING_WHITESPACE.match(line):
        # Within current advisory.
        if not current_advisory:
          raise ValueError('Unexpected tab.')

        # {CVE-XXXX-XXXX CVE-XXXX-XXXX}
        line = line.lstrip()
        if line.startswith('{'):
          advisories[current_advisory].upstream = line.strip('{}').split()
          continue

        if line.startswith('NOTE:'):
          continue

        version_match = VERSION_PATTERN.match(line)
        if not version_match:
          raise ValueError('Invalid version line: ' + line)

        release_name = version_match.group(1)
        package_name = version_match.group(2)
        fixed_ver = version_match.group(3)

        # Only create advisory if the version is affected.
        if fixed_ver != NOT_AFFECTED_VERSION:
          # If fixed version is one of the following special values
          # fixed version essentially doesn't exist, so blank it
          if fixed_ver in [UNFIXED_VERSION, END_OF_LIFE_VERSION]:
            fixed_ver = ''

          advisories[current_advisory].affected.append(
              AffectedInfo(codename_to_version[release_name], package_name,
                           fixed_ver))

      else:
        if line.strip().startswith('NOTE:'):
          continue

        # New advisory.
        dsa_match = DSA_PATTERN.match(line)
        if not dsa_match:
          raise ValueError('Invalid line: ' + line)

        parsed_date = dateutil.parser.parse(
            dsa_match.group(1)).isoformat() + 'Z'
        current_advisory = dsa_match.group(2)
        advisories[current_advisory] = AdvisoryInfo(current_advisory,
                                                    dsa_match.group(3),
                                                    parsed_date)


def parse_webwml_files(advisories: Advisories, webwml_repo_path: str,
                       wml_file_sub_path: str):
  """Parses the webwml file into the advisories object"""
  file_path_map = {}

  for root, _, files in os.walk(
      os.path.join(webwml_repo_path, wml_file_sub_path)):
    for file in files:
      file_path_map[file] = os.path.join(root, file)

  git_relative_paths = collections.defaultdict(list)
  # Add descriptions to advisories from wml files
  for dsa_id, advisory in advisories.items():
    # remove potential extension (e.g. DSA-12345-2, -2 is the extension)
    mapped_key_no_ext = DSA_OR_DLA_WITH_NO_EXT.findall(dsa_id.lower())[0]
    wml_path = file_path_map.get(mapped_key_no_ext + '.wml')
    data_path = file_path_map.get(mapped_key_no_ext + '.data')

    if not wml_path:
      print('No WML file yet for this: ' + mapped_key_no_ext +
            ', creating partial schema')
      continue

    with open(wml_path, encoding='iso-8859-2') as handle:
      data = handle.read()
      html = WML_DESCRIPTION_PATTERN.findall(data)[0]
      res = markdownify.markdownify(html)
      advisory.details = res

    with open(data_path, encoding='utf-8') as handle:
      data: str = handle.read()
      report_date: str = WML_REPORT_DATE_PATTERN.findall(data)[0]

      # Split by ',' here for the occasional case where there
      # are two dates in the 'publish' field.
      # Multiple dates are caused by major modification later on.
      # This is accounted for with the modified timestamp with git
      # below though, so we don't need to parse them here
      advisory.published = (
          datetime.strptime(report_date.split(',')[0], '%Y-%m-%d').isoformat() +
          'Z')

    advisory_url_path = os.path.relpath(
        wml_path, os.path.join(webwml_repo_path, 'english'))
    advisory_url_path = os.path.splitext(advisory_url_path)[0]
    advisory_url = f'{DEBIAN_BASE_URL}/{advisory_url_path}'

    advisory.references.append(Reference('ADVISORY', advisory_url))

    git_relative_path_wml = os.path.relpath(wml_path, webwml_repo_path)
    git_relative_path_data = os.path.relpath(data_path, webwml_repo_path)
    git_relative_paths[git_relative_path_wml].append(dsa_id)
    git_relative_paths[git_relative_path_data].append(dsa_id)

  modified_date_dict = collections.defaultdict(
      lambda: datetime.fromtimestamp(0, timezone.utc))
  current_date = None
  proc = subprocess.Popen([
      'git', 'log', f'--pretty={GIT_DATE_PREFIX}%aI', '--name-only',
      '--author-date-order'
  ],
                          cwd=webwml_repo_path,
                          stdout=subprocess.PIPE)
  # Loop through each commit to get the first time a file is mentioned
  # Save the date as the last modified date of said file
  for line in io.TextIOWrapper(proc.stdout, encoding='utf-8'):
    line = line.strip()
    if not line:
      continue

    if line.startswith(GIT_DATE_PREFIX):
      current_date = datetime.fromisoformat(
          line[len(GIT_DATE_PREFIX):]).astimezone(timezone.utc)
      continue

    dsa_ids = git_relative_paths.pop(line, None)
    if not dsa_ids:
      continue

    for dsa_id in dsa_ids:
      # Set modified date to the latest of the .data and .wml files.
      modified_date_dict[dsa_id] = max(modified_date_dict[dsa_id], current_date)

    # Empty dictionary means no more files need modification dates
    # Safely skip rest of the commits
    if not git_relative_paths:
      break

  for dsa_id, modified_date in modified_date_dict.items():
    # OSV spec requires a "Z" offset
    advisories[dsa_id].modified = modified_date.isoformat().replace(
        '+00:00', 'Z')


def write_output(output_dir: str, advisories: Advisories):
  """Writes the advisory dict into individual json files"""
  for dsa_id, advisory in advisories.items():
    # Skip advisories that do not affect anything
    if len(advisory.affected) == 0:
      print('Skipping: ' + dsa_id + ' because no affected versions')
      continue

    with open(
        os.path.join(output_dir, dsa_id + '.json'), 'w',
        encoding='utf-8') as output_file:
      output_file.write(json.dumps(advisory, default=dumper, indent=2))
      print(
          'Writing: ' + os.path.join(output_dir, dsa_id + '.json'), flush=True)

  print('Complete')


def is_dsa_file(name: str):
  """Check if filename is a DSA output file, e.g. DSA-1234-1.json"""
  return name.startswith('DSA-') and name.endswith('.json')


def convert_debian(webwml_repo: str, security_tracker_repo: str,
                   output_dir: str, adv_type: AdvisoryType):
  """Convert Debian advisory data into OSV."""
  advisories: Advisories = {}

  if adv_type == AdvisoryType.DLA:
    parse_security_tracker_file(advisories, security_tracker_repo,
                                SECURITY_TRACKER_DLA_PATH)
    parse_webwml_files(advisories, webwml_repo, WEBWML_LTS_SECURITY_PATH)
  elif adv_type == AdvisoryType.DSA:
    parse_security_tracker_file(advisories, security_tracker_repo,
                                SECURITY_TRACKER_DSA_PATH)
    parse_webwml_files(advisories, webwml_repo, WEBWML_SECURITY_PATH)
  elif adv_type == AdvisoryType.DTSA:
    parse_security_tracker_file(advisories, security_tracker_repo,
                                SECURITY_TRACKER_DTSA_PATH)
  else:
    raise ValueError('Invalid advisory type')

  write_output(output_dir, advisories)


def main():
  """Main function."""
  parser = argparse.ArgumentParser(description='Debian to OSV converter.')
  parser.add_argument('webwml_repo', help='Debian wml repo')
  parser.add_argument(
      'security_tracker_repo', help='Debian security-tracker repo')
  parser.add_argument(
      '-o', '--output-dir', help='Output directory', required=True)
  parser.add_argument(
      '--adv_type',
      help='Advisory type',
      type=AdvisoryType,
      choices=list(AdvisoryType))
  parser.set_defaults(feature=False)

  args = parser.parse_args()

  convert_debian(args.webwml_repo, args.security_tracker_repo, args.output_dir,
                 args.adv_type)


if __name__ == '__main__':
  main()
