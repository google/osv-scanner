from __future__ import annotations

import os
import sys
from datetime import date

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.

root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, root_path)

# https://docs.readthedocs.io/en/stable/builds.html#build-environment
if "READTHEDOCS" in os.environ:
    import glob

    if glob.glob("../changelog/*.*.rst"):
        print("-- Found changes; running towncrier --", flush=True)
        import subprocess

        subprocess.run(
            ["towncrier", "--yes", "--date", "not released yet"], cwd="..", check=True
        )

import urllib3

# -- General configuration -----------------------------------------------------


# Add any Sphinx extension module names here, as strings. They can be extensions
# coming with Sphinx (named 'sphinx.ext.*') or your custom ones.
extensions = [
    "sphinx.ext.autodoc",
    "sphinx_copybutton",
    "sphinx.ext.doctest",
    "sphinx.ext.intersphinx",
    "sphinxext.opengraph",
]

# Open Graph metadata
ogp_title = "urllib3 documentation"
ogp_type = "website"
ogp_social_cards = {"image": "images/logo.png", "line_color": "#F09837"}
ogp_description = "urllib3 is a user-friendly HTTP client library for Python."

# Test code blocks only when explicitly specified
doctest_test_doctest_blocks = ""

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# The suffix of source filenames.
source_suffix = ".rst"

# The master toctree document.
master_doc = "index"

# General information about the project.
project = "urllib3"
copyright = f"{date.today().year}, Andrey Petrov"

# The short X.Y version.
version = urllib3.__version__
# The full version, including alpha/beta/rc tags.
release = version

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ["_build"]

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = "friendly"

# The base URL with a proper language and version.
html_baseurl = os.environ.get("READTHEDOCS_CANONICAL_URL", "/")

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
html_theme = "furo"
html_favicon = "images/favicon.png"

html_static_path = ["_static"]
html_theme_options = {
    "announcement": """
        <a style=\"text-decoration: none; color: white;\" 
           href=\"https://opencollective.com/urllib3/updates/urllib3-is-fundraising-for-http-2-support\">
           <img src=\"/en/latest/_static/favicon.png\"/> urllib3 is fundraising for HTTP/2 support!
        </a>
    """,
    "sidebar_hide_name": True,
    "light_logo": "banner.svg",
    "dark_logo": "dark-logo.svg",
}

intersphinx_mapping = {"python": ("https://docs.python.org/3", None)}

# Show typehints as content of the function or method
autodoc_typehints = "description"

# Warn about all references to unknown targets
nitpicky = True
# Except for these ones, which we expect to point to unknown targets:
nitpick_ignore = [
    ("py:class", "_TYPE_SOCKS_OPTIONS"),
    ("py:class", "_TYPE_SOCKET_OPTIONS"),
    ("py:class", "_TYPE_TIMEOUT"),
    ("py:class", "_TYPE_FIELD_VALUE"),
    ("py:class", "_TYPE_BODY"),
    ("py:class", "_HttplibHTTPResponse"),
    ("py:class", "_HttplibHTTPMessage"),
    ("py:class", "TracebackType"),
    ("py:class", "email.errors.MessageDefect"),
    ("py:class", "MessageDefect"),
    ("py:class", "http.client.HTTPMessage"),
    ("py:class", "RequestHistory"),
    ("py:class", "SSLTransportType"),
    ("py:class", "VerifyMode"),
    ("py:class", "_ssl._SSLContext"),
    ("py:class", "urllib3._collections.HTTPHeaderDict"),
    ("py:class", "urllib3._collections.RecentlyUsedContainer"),
    ("py:class", "urllib3._request_methods.RequestMethods"),
    ("py:class", "urllib3.contrib.socks._TYPE_SOCKS_OPTIONS"),
    ("py:class", "urllib3.util.timeout._TYPE_DEFAULT"),
    ("py:class", "BaseHTTPConnection"),
]
