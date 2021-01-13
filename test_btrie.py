""" Tests for btrie.c
"""

import os
import re
from subprocess import Popen, PIPE
from tempfile import TemporaryFile, NamedTemporaryFile
import unittest

from rbldnsd import Rbldnsd, ZoneFile

__all__ = [
    'Test_coalesce_lc_node',
    'Test_shorten_lc_node',
    'Test_convert_lc_node_1',
    'Test_convert_lc_node',
    'Test_insert_lc_node',
    'Test_init_tbm_node',
    'Test_add_to_trie',
    'Test_search_trie',
    ]

def deduce_pointer_size(makefile='./Makefile'):
    """ Deduce the pointer size (in the current compilation environment)
    """
    with file(makefile) as f:
        make_vars = dict(
            m.groups()
            for m in (re.match(r'\s*(\w+)\s*=\s*(.*?)\s*\Z', line)
                      for line in f)
            if m is not None)
    cc = make_vars['CC']
    cflags = make_vars['CFLAGS']

    test_c = NamedTemporaryFile(suffix=".c", delete=False)
    test_c.write(r'''
#include <stdio.h>
#ifndef __SIZEOF_POINTER__
# define __SIZEOF_POINTER__ sizeof(void *)
#endif
int main () {
  printf("%u\n", (unsigned)__SIZEOF_POINTER__);
  return 0;
}
''')
    test_c.flush()
    test_c.close()
    src = test_c.name

    try:
        proc = Popen("%(cc)s %(cflags)s -o %(src)s.bin %(src)s && %(src)s.bin"
                     % locals(),
                     shell=True, stdout=PIPE)
        output = proc.stdout.read()
        if proc.wait() != 0:
            raise RuntimeError("test prog exited with code %d"
                               % proc.returncode)
        return int(output)
    finally:
        try:
            os.unlink(src + '.bin')
        except:
            pass

try:
    sizeof_pointer = deduce_pointer_size()
except Exception:
    print("Can not deduce size of pointer. Assuming pointer size of 8.")
    sizeof_pointer = 8

if sizeof_pointer == 8:
    STRIDE = 5
    LC_BYTES_PER_NODE = 7
elif sizeof_pointer == 4:
    STRIDE = 4
    LC_BYTES_PER_NODE = 3
else:
    raise RuntimeError("Unsupported pointer size (%d)" % sizeof_pointer)

def pad_prefix(prefix, plen):
    """Pad prefix on the right with zeros to a full 128 bits
    """
    if not isinstance(prefix, (int, int)):
        raise TypeError("prefix must be an integer")
    if not 0 <= int(plen) <= 128:
        raise ValueError("plen out of range")
    if not 0 <= prefix < (1 << plen):
        raise ValueError("prefix out of range")
    return prefix << (128 - plen)

class BTrie(object):
    """ A class to construct and perform lookups on a btrie.

    Since we do not have python bindings for btrie, we do this in a
    roundabout way by running rbldnsd with a single ip6trie dataset,
    and then querying the rbldnsd to perform the lookup.

    """
    def __init__(self, prefixes, **kwargs):
        self.rbldnsd = Rbldnsd(**kwargs)
        zonedata = (self._zone_entry(*prefix) for prefix in prefixes)
        self.rbldnsd.add_dataset('ip6trie', ZoneFile(zonedata))

    def __enter__(self):
        self.rbldnsd.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        return self.rbldnsd.__exit__(exc_type, exc_value, exc_tb)

    def lookup(self, prefix, plen):
        prefix = pad_prefix(prefix, plen)
        nibbles = '.'.join("%x" % ((prefix >> n) & 0x0f)
                           for n in range(0, 128, 4))
        return self.rbldnsd.query(nibbles + '.example.com')

    def _zone_entry(self, prefix, plen, data):
        prefix = pad_prefix(prefix, plen)
        ip6addr = ':'.join("%x" % ((prefix >> n) & 0xffff)
                           for n in range(112, -16, -16))
        return "%s/%u :1:%s" % (ip6addr, plen, data)

class CaptureOutput(object):
    def __init__(self):
        self._file = TemporaryFile()

    def __del__(self):
        self._file.close()

    def fileno(self):
        return self._file.fileno()

    def __contains__(self, substr):
        return substr in str(self)

    def __str__(self):
        self._file.seek(0, 0)
        return str(self._file.read())


class Test_coalesce_lc_node(unittest.TestCase):
    def test_merge(self):
        # test coverage of coalesce_lc_node
        prefixes = [
            # this prefix is too long for a single LC node
            # but after we stick the TBM node at 0/0 it should
            # just fit into a single LC extension path
            (0, 8 * (LC_BYTES_PER_NODE + 1), "term"),
            # Add a TBM node to shorten the above LC node
            (0, (8 - STRIDE), "root"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0, 8), b"term")
            self.assertEqual(btrie.lookup(1, 8), b"root")

    def test_steal_bits(self):
        # test coverage of coalesce_lc_node
        prefixes = [
            # This prefix is too long for a single LC node.  After we
            # stick the TBM node at 0/0 it should still be too long
            # for a single LC node, but the upper LC node should steal
            # bits from the terminal LC node.
            (0, 8 * (LC_BYTES_PER_NODE + 1) + 1, "term"),
            (0, (8 - STRIDE), "root"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0, 0), b"term")
            self.assertEqual(btrie.lookup(1, 8), b"root")

class Test_shorten_lc_node(unittest.TestCase):
    def test_steal_child(self):
        # test coverage of coalesce_lc_node
        prefixes = [
            # this prefix is too long for a single LC node
            # but after we stick the TBM node at 0/0 it should
            # just fit into a single LC extension path
            (0, 9, "tbm root"),
            (0, 10, "term"),
            # Add a TBM node to shorten the above LC node
            (0, 9 - STRIDE, "root"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0, 8), b"term")
            self.assertEqual(btrie.lookup(1, 8), b"root")

class Test_convert_lc_node_1(unittest.TestCase):
    def test_left_child(self):
        # test coverage of coalesce_lc_node
        prefixes = [
            # create TBM node at depth 1
            (0, 2, "term"),
            (0, 1, "tbm node"),
            # promote to depth 0
            (0, 0, "root"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0, 0), b"term")
            self.assertEqual(btrie.lookup(1, 2), b"tbm node")
            self.assertEqual(btrie.lookup(1, 1), b"root")

    def test_right_child(self):
        # test coverage of coalesce_lc_node
        prefixes = [
            (3, 2, "term"),
            (1, 1, "tbm node"),
            (0, 0, "root"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(3, 2), b"term")
            self.assertEqual(btrie.lookup(2, 2), b"tbm node")
            self.assertEqual(btrie.lookup(0, 1), b"root")

class Test_convert_lc_node(unittest.TestCase):
    def test_left_child(self):
        # test coverage of coalesce_lc_node
        prefixes = [
            # create TBM node at depth STRIDE - 1
            (0, STRIDE, "term"),
            (0, STRIDE - 1, "tbm node"),
            # promote to depth 0
            (0, 0, "root"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0, STRIDE), b"term")
            self.assertEqual(btrie.lookup(1, STRIDE), b"tbm node")
            self.assertEqual(btrie.lookup(1, 1),      b"root")

class Test_insert_lc_node(unittest.TestCase):
    def test_insert_lc_len_1(self):
        prefixes = [
            # create TBM node at depth 1 with TBM extending path
            (0, STRIDE + 2, "term"),
            (0, STRIDE + 1, "tbm ext path"),
            (0, 1, "tbm node"),
            # promote to depth 0
            (0, 0, "root"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0, 0), b"term")
            self.assertEqual(btrie.lookup(1, STRIDE + 2), b"tbm ext path")
            self.assertEqual(btrie.lookup(1, 2), b"tbm node")
            self.assertEqual(btrie.lookup(1, 1), b"root")

    def test_extend_lc_tail_optimization(self):
        prefixes = [
            # create TBM node at depth 1 with LC extending path
            (1, STRIDE + 2, "term"),
            (0, 1, "tbm node"),
            # promote to depth 0
            (0, 0, "root"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(1, STRIDE + 2), b"term")
            self.assertEqual(btrie.lookup(0, 0), b"tbm node")
            self.assertEqual(btrie.lookup(1, 1), b"root")

    def test_coalesce_lc_tail(self):
        prefixes = [
            # create TBM node with LC extending path which starts
            # at a byte boundary.
            (0, 10, "term"),
            (0, 8 - STRIDE, "tbm node"),
            # promote one level
            (0, 7 - STRIDE, "promoted"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0, 0), b"term")
            self.assertEqual(btrie.lookup(1, 9 - STRIDE), b"tbm node")
            self.assertEqual(btrie.lookup(1, 8 - STRIDE), b"promoted")

class Test_init_tbm_node(unittest.TestCase):
    def test_short_lc_children(self):
        # this exercises the convert_lc_node calls in init_tbm_node()
        prefixes = [
            # create TBM node at depth 1, with two LC extending paths
            # from a deep internal node
            (0, 1, "tbm"),
            (0, STRIDE + 2, "term0"),
            (2, STRIDE + 2, "term1"),
            # promote one level
            (0, 0, "root"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0, 0), b"term0")
            self.assertEqual(btrie.lookup(1, STRIDE + 1), b"term1")
            self.assertEqual(btrie.lookup(1, 2), b"tbm")
            self.assertEqual(btrie.lookup(1, 1), b"root")

    def test_long_lc_children(self):
        # this exercises the shorten_lc_node calls in init_tbm_node()
        prefixes = [
            # create TBM node at depth 1, with two LC extending paths
            # from a deep internal node
            (0, 1, "tbm"),
            (0, STRIDE + 9, "term0"),
            (0x100, STRIDE + 9, "term1"),
            # promote one level
            (0, 0, "root"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0, 0), b"term0")
            self.assertEqual(btrie.lookup(1, STRIDE + 1), b"term1")
            self.assertEqual(btrie.lookup(1, 2), b"tbm")
            self.assertEqual(btrie.lookup(1, 1), b"root")

    def test_set_internal_data_for_root_prefix(self):
        # this exercises the "set internal data for root prefix" code
        prefixes = [
            # create TBM node at depth 1, with internal prefix data
            # and an extending path on a deep internal node
            (0, 1, "tbm"),
            (0, STRIDE, "int data"),
            (0, STRIDE + 1, "ext path"),
            # promote one level
            (0, 0, "root"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0, 0), b"ext path")
            self.assertEqual(btrie.lookup(1, STRIDE + 1), b"int data")
            self.assertEqual(btrie.lookup(1, 2), b"tbm")
            self.assertEqual(btrie.lookup(1, 1), b"root")

    def test_set_right_ext_path(self):
        # this exercises the insert_lc_node(right_ext) call in init_tbm_node()
        # this also exercises next_pbyte with (pos + TBM_STRIDE) % 8 == 0
        prefixes = [
            # create TBM node at depth (9 - STRIDE) with a right TBM
            # extending path on a deep internal node
            (0, 9 - STRIDE, "tbm"),
            (1, 9, "ext path"),
            (2, 10, "term"),
            # promote one level to depth (8 - STRIDE)
            (0, 8 - STRIDE, "top"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0, 0), b"tbm")
            self.assertEqual(btrie.lookup(2, 10), b"term")
            self.assertEqual(btrie.lookup(3, 10), b"ext path")
            self.assertEqual(btrie.lookup(1, 9 - STRIDE), b"top")

class Test_add_to_trie(unittest.TestCase):
    def test_duplicate_terminal_lc(self):
        prefixes = [
            (0, 1, "term"),
            (0, 1, "term"),
            ]
        stderr = CaptureOutput()
        with BTrie(prefixes, stderr=stderr) as btrie:
            self.assertEqual(btrie.lookup(0, 0), b"term")
        self.assertTrue("duplicated entry for" in stderr,
                        "No duplicated entry error message in stderr: %r"
                        % str(stderr))

    def test_duplicate_internal_data(self):
        prefixes = [
            (0, 0, "root"),
            (2, 3, "term"),
            (2, 3, "term"),
            ]
        stderr = CaptureOutput()
        with BTrie(prefixes, stderr=stderr) as btrie:
            self.assertEqual(btrie.lookup(4, 4), b"term")
            self.assertEqual(btrie.lookup(0, 0), b"root")

        self.assertTrue("duplicated entry for" in stderr,
                        "No duplicated entry error message in stderr: %r" % stderr)

    def test_split_first_byte_of_lc_prefix(self):
        # this is for coverage of common_prefix()
        prefixes = [
            (0x1234, 16, "long"),
            (0x1000, 16, "splitter"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0x1234, 16), b"long")
            self.assertEqual(btrie.lookup(0x1000, 16), b"splitter")

    def test_split_last_byte_of_lc_prefix(self):
        # this is for coverage of common_prefix()
        prefixes = [
            (0x1234, 15, "long"),
            (0x1238, 15, "splitter"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0x1234, 15), b"long")
            self.assertEqual(btrie.lookup(0x1238, 15), b"splitter")

class Test_search_trie(unittest.TestCase):
    def test_tbm_root_data(self):
        # test access to root internal node in a TBM node
        prefixes = [(0, 127, "tbm root"),
                    (1, 128, "int data")]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0, 0), b"tbm root")

    def test_tbm_internal_data(self):
        # test access to each (non-root) internal node in a TBM node
        for plen in range(1, STRIDE):
            # TBM node
            prefixes = [(0, 128 - plen, "tbm root")]
            prefixes.extend((pfx, 128, "%u/%u" % (pfx, plen))
                            for pfx in range(1 << plen))
            with BTrie(prefixes) as btrie:
                for pfx in range(1 << plen):
                    self.assertEqual(btrie.lookup(pfx, 128), bytes("%u/%u" % (pfx, plen), encoding='utf8') )

    def test_tbm_extending_paths(self):
        # test access to each extended path of a TBM node
        prefixes = [(0,0,"root")] # make sure to create top-level TBM node
        prefixes.extend((pfx, STRIDE, str(pfx)) for pfx in range(1 << STRIDE))
        with BTrie(prefixes) as btrie:
            for pfx in range(1 << STRIDE):
                self.assertEqual(btrie.lookup(pfx, STRIDE), bytes(str(pfx), encoding='utf8'))

    def test_no_match(self):
        prefixes = [
            (1, 2, "term"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0,0), None)

    def test_follow_lc(self):
        prefixes = [
            (0, 2 * STRIDE, "term"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0,0), b"term")

    def test_parents_internal_data(self):
        prefixes = [
            (0, 0, "root"),
            (2, 2, "int data"),
            (0x200, 10, "term"),
            ]
        with BTrie(prefixes) as btrie:
            self.assertEqual(btrie.lookup(0x201, 10), b"int data")

if __name__ == '__main__':
    unittest.main()
