""" Run an rbldnsd and send it DNS queries.


"""
import errno
from itertools import count
import subprocess
from tempfile import NamedTemporaryFile, TemporaryFile
import time
import unittest

try:
    import DNS
except ImportError:
    raise RuntimeError("The python3-dns library is not installed...")
try:
    from DNS import SocketError as DNS_SocketError
except ImportError:
    class DNS_SocketError(Exception):
        """ Dummy, never raised.
        """

DUMMY_ZONE_HEADER = """
$SOA 0 example.org. hostmaster.example.com. 0 1h 1h 2d 1h
$NS 1d ns0.example.org
"""

class ZoneFile(object):
    def __init__(self, lines=None, no_header=False):
        self._file = NamedTemporaryFile(delete=False)
        if not no_header:
            self._file.write(bytes(DUMMY_ZONE_HEADER, encoding = 'utf-8'))
        if lines is not None:
            self.writelines(lines)
        self._file.flush()

    def __del__(self):
        self._file.close()

    @property
    def name(self):
        return self._file.name

    def write(self, str):
        self._file.write(bytes(str))
        self._file.flush()

    def writelines(self, lines):
        self._file.writelines(bytes("%s\n" % line, encoding = 'utf-8') for line in lines)
        self._file.flush()

class DaemonError(Exception):
    """ Various errors having to do with the execution of the daemon.
    """

class QueryRefused(Exception):
    """ Query to rbldnsd was REFUSED.
    """


class Rbldnsd(object):
    def __init__(self, datasets=None,
                 daemon_addr='localhost', daemon_port=5300,
                 daemon_bin='./rbldnsd',
                 stderr=None):
        self._daemon = None
        self.datasets = []
        self.daemon_addr = daemon_addr
        self.daemon_port = daemon_port
        self.daemon_bin = daemon_bin
        self.stderr = stderr

    def add_dataset(self, ds_type, file, soa='example.com'):
        self.datasets.append((soa, ds_type, file))

    def __enter__(self):
        self._start_daemon()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self._stop_daemon()

    def __del__(self):
        if self._daemon:
            self._stop_daemon()

    def query(self, name, qtype='TXT'):
        if not self._daemon:
            raise DaemonError("daemon not running")
        elif self._daemon.poll() is not None:
            raise DaemonError("daemon has died with code %d"
                              % self._daemon.returncode)

        req = DNS.Request(name=name, qtype=qtype, rd=0)
        resp = req.req(server=self.daemon_addr, port=self.daemon_port)
        status = resp.header['status']
        if status == 'REFUSED':
            raise QueryRefused("REFUSED")
        elif status == 'NXDOMAIN':
            return None
        else:
            assert status == 'NOERROR'
            assert len(resp.answers) == 1
            assert len(resp.answers[0]['data']) == 1
            return resp.answers[0]['data'][0]

    def _start_daemon(self):
        if len(self.datasets) == 0:
            raise ValueError("no datasets defined")

        cmd = [ self.daemon_bin, '-n',
                '-b', '%s/%u' % (self.daemon_addr, self.daemon_port),
                ]
        for zone, ds_type, file in self.datasets:
            if isinstance(file, str):
                filename = file
            else:
                filename = file.name
            cmd.append("%s:%s:%s" % (zone, ds_type, filename))

        self._stdout = TemporaryFile()
        self._daemon = daemon = subprocess.Popen(cmd, stdout=self._stdout,
                                                 stderr=self.stderr)

        # wait for rbldnsd to start responding
        for retry in count():
            if daemon.poll() is not None:
                raise DaemonError(
                    "rbldsnd exited unexpectedly with return code %d"
                    % daemon.returncode)
            try:
                self.query('dummy.nonexisting.zone')
                break
            except QueryRefused:
                break
            except DNS_SocketError as ex:
                # pydns >= 2.3.6
                wrapped_error = ex.args[0]
                if wrapped_error.errno != errno.ECONNREFUSED:
                    raise
            except DNS.DNSError as ex:
                # pydns < 2.3.6
                if str(ex) != 'no working nameservers found':
                    raise
            if retry > 10:
                raise DaemonError("rbldnsd does not seem to be responding")
            time.sleep(0.1)

    def _stop_daemon(self):
        daemon = self._daemon

        if daemon.poll() is None:
            daemon.terminate()
            retries = count()
            while daemon.poll() is None:
                retry = next(retries)
                if retry == 30:
                    daemon.kill()
                elif retry == 50:
                    raise DaemonError("can not kill stop rbldnsd")
                time.sleep(0.1)

        self._stdout.close()

        self._daemon = None
        if daemon.returncode != 0:
            raise DaemonError("rbldnsd exited with code %d"
                              % daemon.returncode)

    @property

    def no_ipv6(self):
        """ Was rbldnsd compiled with -DNO_IPv6?
        """
        # If rbldnsd was compiled with -DNO_IPv6, the (therefore
        # unsupported) '-6' command-line switch will not be described
        # in the help message
        cmd = [self.daemon_bin, '-h']
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        help_message = proc.stdout.readlines()
        if proc.wait() != 0:
            raise subprocess.CalledProcessError(proc.returncode, cmd)

        return not any(line.lstrip().startswith(b'-6 ')
                       for line in help_message)


class TestRbldnsd(unittest.TestCase):
    def test(self):
        rbldnsd = Rbldnsd()
        test_zone = ZoneFile(lines=["1.2.3.4 :1: Success"])
        rbldnsd.add_dataset('ip4set', test_zone)
        with rbldnsd:
            self.assertEqual(rbldnsd.query('4.3.2.1.example.com'), 'Success')
            self.assertEqual(rbldnsd.query('5.3.2.1.example.com'), None)

if __name__ == '__main__':
    unittest.main()
