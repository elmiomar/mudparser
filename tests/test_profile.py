#!/usr/bin/env python

import unittest

# import importlib

# if importlib.util.find_spec("mudparser") is None:
#     # if complaining about module not existing (this happens when running test from terminal)
#     import sys
#     import os
#     here = os.path.dirname(os.path.abspath(__file__))
#     sys.path.append(os.path.join(here, '..'))

from mudparser.profile import Profile


class TestCaseProfile(unittest.TestCase):
    """Tests for 'profile.py'."""

    # test example
    def test_parse(self):
        with open('../data/amazon_echo_short.json') as json_file:
            profile = Profile(json_file)
            expected = 'https://amazonecho.com/amazonecho'
            actual = profile.url
            self.assertEqual(actual, expected, "expected {} got {}".format(expected, actual))

            # number of acls should be = 1
            self.assertEqual(len(profile.acls), 1, "expected {} got {}".format(1, len(profile.acls)))

            # number of entries in acl with name = 'from-ipv4-amazonecho'
            acl = profile.acls['from-ipv4-amazonecho']
            self.assertEqual(len(acl.entries), 3, "expected {} got {}".format(3, len(acl.entries)))

    # dummy test to test unittest is working fine
    def test_this_should_succeed(self):
        self.assertEqual(True, True)


if __name__ == '__main__':
    unittest.main()
