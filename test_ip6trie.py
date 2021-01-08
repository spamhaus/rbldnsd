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

class TestIp6TrieDataset(unittest.TestCase):
    def test_exclusion(self):
        with ip6trie(["dead::/16 listed",
                      "!dead::beef"]) as dnsd:
            self.assertEqual(dnsd.query(rfc3152("dead::beef")), None)
            self.assertEqual(dnsd.query(rfc3152("dead::beee")), b"listed")


def rfc3152(ip6addr, domain='example.com'):
    return "%s.%s" % ('.'.join(reversed(_to_nibbles(ip6addr))), domain)

def _to_nibbles(ip6addr):
    """ Convert ip6 address (in rfc4291 notation) to a sequence of nibbles

    NB: We avoid the use of socket.inet_pton(AF_INET6, ip6addr) here
    because it fails (with 'error: can't use AF_INET6, IPv6 is
    disabled') when python has been compiled without IPv6 support. See
    http://www.corpit.ru/pipermail/rbldnsd/2013q3/001181.html

    """
    def _split_words(addr):
        return [ int(w, 16) for w in addr.split(':') ] if addr else []

    if '::' in ip6addr:
        head, tail = [ _split_words(s) for s in ip6addr.split('::', 1) ]
        nzeros = 8 - len(head) - len(tail)
        assert nzeros >= 0
        words = head + [ 0 ] * nzeros + tail
    else:
        words = _split_words(ip6addr)

    assert len(words) == 8
    for word in words:
        assert 0 <= word <= 0xffff

    return ''.join("%04x" % word for word in words)

if __name__ == '__main__':
    unittest.main()
