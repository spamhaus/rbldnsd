""" Convenience script to run all python test cases in one go.
"""
import sys
import unittest

try:
    import DNS
except ImportError:
    print("TESTS SKIPPED: the python3-dns library is not installed")
    sys.exit(0)

from test_btrie import *
from test_ip6trie import *
from test_ip4trie import *
from test_acl import *

if __name__ == '__main__':
    unittest.main()
