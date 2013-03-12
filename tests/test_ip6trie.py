""" Basic ip6trie dataset Tests
"""
import unittest

from rbldnsd import Rbldnsd, ZoneFile

__all__ = [
    'TestIp6TrieDataset',
    ]

def ip6trie(zone_data):
    """ Run rbldnsd with an ip6trie dataset
    """
    dnsd = Rbldnsd()
    dnsd.add_dataset('ip6trie', ZoneFile(zone_data))
    return dnsd

def rfc3152(ip6addr, domain='example.com'):
    from socket import inet_pton, AF_INET6
    from struct import unpack

    bytes = unpack("16B", inet_pton(AF_INET6, ip6addr))
    nibbles = '.'.join("%x.%x" % (byte & 0xf, (byte >> 4) & 0xf)
                       for byte in reversed(bytes))
    return "%s.%s" % (nibbles, domain)

class TestIp6TrieDataset(unittest.TestCase):
    def test_exclusion(self):
        with ip6trie(["dead::/16 listed",
                      "!dead::beef"]) as dnsd:
            self.assertEqual(dnsd.query(rfc3152("dead::beef")), None)
            self.assertEqual(dnsd.query(rfc3152("dead::beee")), "listed")

if __name__ == '__main__':
    unittest.main()
