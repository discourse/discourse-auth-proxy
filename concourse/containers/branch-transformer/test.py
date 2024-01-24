#!/usr/bin/env python3

"""
Exercise the transform program.

Sample inputs are fed to the transform program on stdin.
The transform program writes its output to stdout.
This test program compares actual output with expected output,
and exits with non-zero status upon any mismatch.
"""

# This test program is automatically executed on container build.
# Test dependencies, namely pytest, are supplied by the container image.
#
# This file must have a .py extension.
# pytest maintainers refuse to allow test collection otherwise.

# pylint: disable=missing-function-docstring

import argparse
import json
import os
import sys
import tempfile
import subprocess
from contextlib import ExitStack

import pytest


def test_null():
    assert run_prog([]) == []


def test_ignores_plumbing_branch():
    assert run_prog([{"name": "plumbing"}]) == []


def test_ignores_trunkish_branch():
    assert (run_prog([{"name": "main"},
                      {"name": "master"}])
            == [])


def test_topic_branch():
    assert (run_prog([{"name": "bobtest"}])
            ==
            [{"name": "bobtest",
              "tag":  "bobtest"}])
    assert (run_prog([{"name": "bob-test"}])
            ==
            [{"name": "bob-test",
              "tag":  "bob-test"}])

    # use - as a substitute for characters that would not be valid in a tag
    assert (run_prog([{"name": "bob/frob"}])
            ==
            [{"name": "bob/frob",
              "tag":  "bob-frob"}])
    assert (run_prog([{"name": "bob/-frob"}])
            ==
            [{"name": "bob/-frob",
              "tag":  "bob-frob"}])


PROG = os.environ.get("TEST_PROG")  # see bottom


def run_prog(input_obj):
    with ExitStack() as st:
        fi = st.enter_context(tempfile.TemporaryFile(mode="w+", encoding="utf8"))
        fo = st.enter_context(tempfile.TemporaryFile(mode="w+", encoding="utf8"))
        json.dump(input_obj, fi)
        fi.seek(0)
        subprocess.run([PROG], stdin=fi, stdout=fo, check=True)
        fo.seek(0)
        return json.load(fo)


class Args:

    @classmethod
    def parse(cls, argv=None):
        if argv is None:
            argv = sys.argv
        parser = argparse.ArgumentParser()
        parser.add_argument("transform-prog",
                            help="Path to the program under test.")
        args = parser.parse_args(argv[1:])
        return cls(args)

    def __init__(self, args):
        self._args = args

    def __getattr__(self, name):
        return getattr(self._args, name)

    @property
    def prog(self):
        return getattr(self, "transform-prog")


def main(argv=None):
    if not argv:
        argv = sys.argv
    # Global bindings we make here are not visible when pytest is executing,
    # probably because it (re)imports the module.  ¯\_(ツ)_/¯
    # Funnel whatever we need through the process environment instead.
    args = Args.parse(argv)
    os.environ["TEST_PROG"] = args.prog
    return pytest.main(["-vv",         # dump full structured diffs upon any mismatch
                        "-o", "console_output_style=classic",
                                       # suppress useless progress markers
                        "--tb=short",  # suppress outrageously verbose tracebacks
                        argv[0]])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
