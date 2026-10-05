"""Unit tests: verify OPEN / CLOSED / FILTERED classification, including simulated
firewall behaviour (silent drop -> timeout, ICMP unreachable)."""
import errno, socket, unittest
from unittest import mock
import port_scanner as ps


class FakeSock:
    def __init__(self, connect_result=None, connect_exc=None):
        self.connect_result, self.connect_exc = connect_result, connect_exc
    def settimeout(self, t): pass
    def connect_ex(self, addr):
        if self.connect_exc:
            raise self.connect_exc
        return self.connect_result
    def recv(self, n): return b"SSH-2.0-Test\r\n"
    def sendall(self, d): pass
    def close(self): pass


def scan_with(fake):
    with mock.patch("port_scanner.socket.socket", return_value=fake):
        return ps.scan_port("192.0.2.1", 22, 1.0, True)


class Classification(unittest.TestCase):
    def test_open(self):
        r = scan_with(FakeSock(connect_result=0))
        self.assertEqual(r["state"], ps.OPEN)
        self.assertIn("responsive", r["detail"])

    def test_closed_on_rst(self):
        self.assertEqual(scan_with(FakeSock(connect_result=errno.ECONNREFUSED))["state"], ps.CLOSED)

    def test_filtered_on_silent_drop(self):
        self.assertEqual(scan_with(FakeSock(connect_exc=socket.timeout()))["state"], ps.FILTERED)

    def test_filtered_on_host_unreachable(self):
        self.assertEqual(scan_with(FakeSock(connect_result=errno.EHOSTUNREACH))["state"], ps.FILTERED)

    def test_port_parsing(self):
        self.assertEqual(ps.parse_ports("22,80,100-102"), [22, 80, 100, 101, 102])
        with self.assertRaises(ValueError):
            ps.parse_ports("0-5")


if __name__ == "__main__":
    unittest.main(verbosity=2)
