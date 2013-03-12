""" Tests for the acl dataset
"""
from tempfile import NamedTemporaryFile
import unittest

from rbldnsd import ZoneFile, Rbldnsd, QueryRefused

__all__ = [
    'TestAclDataset',
    ]

def daemon(acl, addr='localhost'):
    """ Create an Rbldnsd instance with given ACL
    """
    acl_zone = NamedTemporaryFile()
    acl_zone.writelines("%s\n" % line for line in acl)
    acl_zone.flush()

    dnsd = Rbldnsd(daemon_addr=addr)
    dnsd.add_dataset('acl', acl_zone)
    dnsd.add_dataset('generic', ZoneFile(['test TXT "Success"']))
    return dnsd

class TestAclDataset(unittest.TestCase):
    def test_refuse_ipv4(self):
        with daemon(acl=["127.0.0.1 :refuse"],
                    addr='127.0.0.1') as dnsd:
            self.assertRaises(QueryRefused, dnsd.query, 'test.example.com')

    def test_pass_ipv4(self):
        with daemon(acl=[ "0.0.0.0/0 :refuse",
                          "127.0.0.1 :pass" ],
                    addr='127.0.0.1') as dnsd:
            self.assertEqual(dnsd.query('test.example.com'), 'Success')

    def test_refuse_ipv6(self):
        with daemon(acl=["::1 :refuse"],
                    addr='::1') as dnsd:
            self.assertRaises(QueryRefused, dnsd.query, 'test.example.com')

    def test_pass_ipv6(self):
        with daemon(acl=[ "0/0 :refuse",
                          "0::1 :pass" ],
                    addr='::1') as dnsd:
            self.assertEqual(dnsd.query('test.example.com'), 'Success')

if __name__ == '__main__':
    unittest.main()
