""" Tests for the acl dataset
"""
from functools import wraps
import socket
import sys
from tempfile import NamedTemporaryFile
import unittest

from rbldnsd import ZoneFile, Rbldnsd, QueryRefused

__all__ = [
    'TestAclDataset',
    ]

try:
    from unittest import skipIf
except ImportError:
    # hokey replacement (for python <= 2.6)
    def skipIf(condition, reason):
        if condition:
            def decorate(f):
                @wraps(f)
                def skipped(*args, **kw):
                    sys.stderr.write("skipped test: %s " % reason)
                return skipped
            return decorate
        else:
            return lambda f: f

try:
    # check for ipv6 support in python, kernel, libc
    socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).close()
except (socket.error, AttributeError):
    no_ipv6 = True
else:
    # check for ipv6 support in rbldnsd
    no_ipv6 = Rbldnsd().no_ipv6

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

    @skipIf(no_ipv6, "IPv6 unsupported")
    def test_refuse_ipv6(self):
        with daemon(acl=["::1 :refuse"],
                    addr='::1') as dnsd:
            self.assertRaises(QueryRefused, dnsd.query, 'test.example.com')

    @skipIf(no_ipv6, "IPv6 unsupported")
    def test_pass_ipv6(self):
        with daemon(acl=[ "0/0 :refuse",
                          "0::1 :pass" ],
                    addr='::1') as dnsd:
            self.assertEqual(dnsd.query('test.example.com'), 'Success')

if __name__ == '__main__':
    unittest.main()
