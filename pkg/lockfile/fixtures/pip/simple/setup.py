#!/usr/bin/env python

from distutils.core import setup

setup(
  name="test_package",
  version="1.0.2",
  install_requires=[
    "Jinja2~=2.7.2",
    "Django>=1.6.1",
    "python-etcd<=0.4.5",
    "Django-Select2>6.0.1",  # this version installs with lowercase so it catches a previous bug in pip_resolve.py
    "irc<16.2",  # this has a cyclic dependecy (interanl jaraco.text <==> jaraco.collections)
    "testtools===2.3.0",  # this has a cycle (fixtures ==> testtols)
    "requests!=2.3.0",
    "tensorflow==2.17.0",
  ],
)
