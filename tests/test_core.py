import os
import tempfile
import unittest

from golang_tcp import (
    ConnectionEntry,
    TcpState,
    parse_proc_net_tcp,
    parse_proc_net_tcp6,
    parse_proc_net_tcp_text,
)


TCP_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
    "   uid  timeout inode\n"
)


TCP_LINE = (
    "   0: 0100007F:E8D4 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
    "     0        0 30450 1 ffff8801a0a1a000 100 0 0 10 0\n"
)


class ParseProcNetTcpTextTest(unittest.TestCase):
    def test_parses_ipv4_listening_socket(self):
        entries = parse_proc_net_tcp_text(TCP_HEADER + TCP_LINE, ipv6=False)
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertIsInstance(e, ConnectionEntry)
        self.assertEqual(e.local_address, "127.0.0.1")
        self.assertEqual(e.local_port, 0xE8D4)
        self.assertEqual(e.remote_address, "0.0.0.0")
        self.assertEqual(e.remote_port, 0)
        self.assertEqual(e.state, TcpState.LISTEN)
        self.assertEqual(e.state_name, "LISTEN")
        self.assertEqual(e.uid, 0)
        self.assertEqual(e.inode, 30450)

    def test_decodes_keepalive_timer(self):
        line = (
            "   0: 0100007F:E8D4 0100007F:0050 01 00000000:00000000 13:00000012 00000000"
            "     0        0 30450 1 ffff8801a0a1a000 100 0 0 10 0\n"
        )
        entries = parse_proc_net_tcp_text(TCP_HEADER + line, ipv6=False)
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertTrue(e.timer_pending)
        self.assertEqual(e.timer_jiffies, 0x09)
        self.assertEqual(e.timer_name, "keepalive")
        self.assertEqual(e.retransmissions, 0)

    def test_decodes_retrans_timer(self):
        line = (
            "   1: 0100007F:E8D4 0100007D:0050 01 00000000:00000000 80:00000001 00000002"
            "     0        0 30451 1 ffff8801a0a1a001 100 0 0 10 0\n"
        )
        entries = parse_proc_net_tcp_text(TCP_HEADER + line, ipv6=False)
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertFalse(e.timer_pending)
        self.assertEqual(e.timer_name, "retrans")
        self.assertEqual(e.timer_jiffies, 0)
        self.assertEqual(e.retransmissions, 0)

    def test_unknown_state_yields_unknown_name(self):
        line = (
            "   0: 0100007F:E8D4 00000000:0000 FF 00000000:00000000 00:00000000 00000000"
            "     0        0 30450 1 ffff8801a0a1a000 100 0 0 10 0\n"
        )
        entries = parse_proc_net_tcp_text(TCP_HEADER + line, ipv6=False)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].state_name, "UNKNOWN_FF")

    def test_blank_and_short_lines_are_skipped(self):
        text = TCP_HEADER + "\n" + TCP_LINE + "   garbage not enough fields\n"
        entries = parse_proc_net_tcp_text(text, ipv6=False)
        self.assertEqual(len(entries), 1)

    def test_ipv6_loopback_parsed(self):
        header = (
            "  sl  local_address                         remote_address"
            "                        st tx_queue rx_queue tr tm->when retrnsmt"
            "   uid  timeout inode\n"
        )
        # 00000000 00000000 00000000 00000001 in little-endian-per-word form
        # is the IPv6 loopback ::1. Port 0050 = 80.
        line = (
            "   0: 00000000000000000000000001000000:0050"
            " 00000000000000000000000000000000:0000 0A"
            " 00000000:00000000 00:00000000 00000000"
            "     0        0 30460 1 ffff8801a0a1a002 100 0 0 10 0\n"
        )
        entries = parse_proc_net_tcp_text(header + line, ipv6=True)
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual(e.local_address, "0000:0000:0000:0000:0000:0000:0000:0001")
        self.assertEqual(e.local_port, 80)
        self.assertEqual(e.state, TcpState.LISTEN)


class ParseProcNetTcpFileTest(unittest.TestCase):
    def test_reads_ipv4_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(TCP_HEADER + TCP_LINE)
            path = f.name
        try:
            entries = parse_proc_net_tcp(path)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].local_address, "127.0.0.1")
        finally:
            os.unlink(path)

    def test_reads_ipv6_file(self):
        header = (
            "  sl  local_address                         remote_address"
            "                        st tx_queue rx_queue tr tm->when retrnsmt"
            "   uid  timeout inode\n"
        )
        line = (
            "   0: 00000000000000000000000001000000:0050"
            " 00000000000000000000000000000000:0000 0A"
            " 00000000:00000000 00:00000000 00000000"
            "     0        0 30460 1 ffff8801a0a1a002 100 0 0 10 0\n"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(header + line)
            path = f.name
        try:
            entries = parse_proc_net_tcp6(path)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].local_port, 80)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
