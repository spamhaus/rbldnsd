""" (Very) basic ip4trie dataset tests
"""
import unittest

from rbldnsd import Rbldnsd, ZoneFile

__all__ = [
    'TestIp4TrieDataset',
    ]

def ip4trie(zone_data):
    """ Run rbldnsd with an ip4trie dataset
    """
    dnsd = Rbldnsd()
    dnsd.add_dataset('ip4trie', ZoneFile(zone_data))
    return dnsd

def reversed_ip(ip4addr, domain='example.com'):
    revip = '.'.join(reversed(ip4addr.split('.')))
    return "%s.%s" % (revip, domain)

class TestIp4TrieDataset(unittest.TestCase):
    def test_exclusion(self):
        with ip4trie(["1.2.3.0/24 listed",
                      "!1.2.3.4"]) as dnsd:
            self.assertEqual(dnsd.query(reversed_ip("1.2.3.4")), None)
            self.assertEqual(dnsd.query(reversed_ip("1.2.3.3")), b"listed")
            self.assertEqual(dnsd.query(reversed_ip("1.2.3.5")), b"listed")

    def test_wildcard_prefix(self):
        with ip4trie(["0/0 wild",
                      "127.0.0.1 localhost"]) as dnsd:
            self.assertEqual(dnsd.query(reversed_ip("127.0.0.1")), b"localhost")
            self.assertEqual(dnsd.query(reversed_ip("0.0.0.0")),   b"wild")
            self.assertEqual(dnsd.query(reversed_ip("127.0.0.2")), b"wild")

if __name__ == '__main__':
    unittest.main()
