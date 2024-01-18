"""
Invoke entrypoint, import here all the tasks we want to make available
"""

from invoke import Collection

from .go import (
  generate_licenses,
  deps_vendored,
  lint_licenses
)

# the root namespace
ns = Collection()

ns.add_task(deps_vendored)
ns.add_task(generate_licenses)
ns.add_task(lint_licenses)
ns.configure(
    {
        'run': {
            # this should stay, set the encoding explicitly so invoke doesn't
            # freak out if a command outputs unicode chars.
            'encoding': 'utf-8',
        }
    }
)
