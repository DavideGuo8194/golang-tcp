from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import IO, Iterator, List, Optional, Tuple


class TcpState(IntEnum):
    """Enumeration of TCP connection states as used by the Linux kernel.

    The numeric values match the kernel's internal state numbers found in
    include/net/tcp_states.h of the Linux source tree.
    """

    ESTABLISHED = 1
    SYN_SENT = 2
    SYN_RECV = 3
    FIN_WAIT1 = 4
    FIN_WAIT2 = 5
    TIME_WAIT = 6
    CLOSE = 7
    CLOSE_WAIT = 8
    LAST_ACK = 9
    LISTEN = 10
    CLOSING = 11
    NEW_SYN_RECV = 12


_STATE_NAMES = {
    1: "ESTABLISHED",
    2: "SYN_SENT",
    3: "SYN_RECV",
    4: "FIN_WAIT1",
    5: "FIN_WAIT2",
    6: "TIME_WAIT",
    7: "CLOSE",
    8: "CLOSE_WAIT",
    9: "LAST_ACK",
    10: "LISTEN",
    11: "CLOSING",
    12: "NEW_SYN_RECV",
}


def _decode_state(state_hex: str) -> Tuple[TcpState, str]:
    """Decode a hexadecimal state code into a TcpState and its printable name.

    If the kernel exposes a state this library does not model, the name is
    UNKNOWN_<hex> so the data is still visible to the caller instead of being
    silently dropped.
    """
    try:
        state_int = int(state_hex, 16)
    except ValueError:
        state_int = -1
    name = _STATE_NAMES.get(state_int)
    if name is None:
        return TcpState.CLOSE, "UNKNOWN_" + state_hex
    return TcpState(state_int), name


def _decode_timer(timer_hex: str) -> Tuple[bool, int, str, int, str]:
    """Decode the timer field into (pending, jiffies, name, retrans, raw).

    The field is of the form ``TR:TM->WHEN``; only the ``TR`` part carries the
    packed timer bits.

    Layout, per net/ipv4/tcp_ipv4.c:440 in the kernel:
      bit 0    : timer is pending
      bits 1-6 : remaining time in clock ticks (jiffies)
      bits 7-10: which timer (0 keepalive, 1 retrans, 2 time-wait, 3 probe)
      bits 11+: number of unacked retransmissions
    """
    tr = timer_hex.split(":", 1)[0] if ":" in timer_hex else timer_hex
    try:
        value = int(tr, 16)
    except ValueError:
        return (False, 0, "unknown", 0, timer_hex)
    pending = bool(value & 0x01)
    jiffies = (value >> 1) & 0x3F
    timer_idx = (value >> 7) & 0x0F
    timer_name = {0: "keepalive", 1: "retrans", 2: "time_wait", 3: "probe"}.get(
        timer_idx, "unknown"
    )
    retrans = (value >> 11) & 0xFFFF
    return (pending, jiffies, timer_name, retrans, timer_hex)


def _parse_addr_port(ip_hex: str, port_hex: str, ipv6: bool) -> Tuple[str, int]:
    """Parse an address:port pair into a colon-separated IP string and integer port.

    For IPv4 the address is a single 32-bit hex word; for IPv6 it is four 32-bit
    words in little-endian order within each word.
    """
    try:
        port = int(port_hex, 16)
    except ValueError:
        port = 0

    if ipv6:
        if len(ip_hex) != 32:
            return (ip_hex, port)
        words = [ip_hex[i : i + 8] for i in range(0, 32, 8)]
        groups: List[str] = []
        for w in words:
            groups.append(w[6:8] + w[4:6])
            groups.append(w[2:4] + w[0:2])
        return (":".join(groups), port)

    if len(ip_hex) != 8:
        return (ip_hex, port)
    b = bytes.fromhex(ip_hex)
    ip = ".".join(str(x) for x in [b[3], b[2], b[1], b[0]])
    return (ip, port)


@dataclass(frozen=True)
class ConnectionEntry:
    """A single parsed TCP socket record from /proc/net/tcp or /proc/net/tcp6.

    The address strings are the raw, colon-separated forms produced by the
    parser: dotted-decimal for IPv4 and fully-expanded 16-bit-hex groups for
    IPv6. Normalising or compressing the IPv6 form is out of scope; callers who
    need RFC 5952 compressed form should post-process with the standard library's
    ipaddress module.
    """

    index: int
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: TcpState
    state_name: str
    tx_queue: int
    rx_queue: int
    timer_pending: bool
    timer_jiffies: int
    timer_name: str
    retransmissions: int
    uid: int
    timeout: int
    inode: int
    raw_line: str


def _parse_line(line: str, line_index: int, ipv6: bool) -> Optional[ConnectionEntry]:
    """Parse a single data line into a ConnectionEntry, or None if malformed.

    Returns None rather than raising so that a single unparseable line never
    aborts a whole-file parse — the kernel format is stable but exotic fields
    (e.g. an unrecognised state) should not take down the whole report.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("sl"):
        return None

    parts = stripped.split()
    if len(parts) < 17:
        return None

    local_addr_port = parts[1].split(":")
    remote_addr_port = parts[2].split(":")
    if len(local_addr_port) != 2 or len(remote_addr_port) != 2:
        return None

    local_addr, local_port = _parse_addr_port(
        local_addr_port[0], local_addr_port[1], ipv6
    )
    remote_addr, remote_port = _parse_addr_port(
        remote_addr_port[0], remote_addr_port[1], ipv6
    )

    state, state_name = _decode_state(parts[3])

    tx_rx = parts[4].split(":")
    if len(tx_rx) != 2:
        return None
    try:
        tx_queue = int(tx_rx[0], 16)
        rx_queue = int(tx_rx[1], 16)
    except ValueError:
        return None

    timer_pending, timer_jiffies, timer_name, retrans, _raw_timer = _decode_timer(parts[5])

    try:
        uid = int(parts[7], 10)
        timeout = int(parts[8], 10)
        inode = int(parts[9], 10)
    except ValueError:
        return None

    return ConnectionEntry(
        index=line_index,
        local_address=local_addr,
        local_port=local_port,
        remote_address=remote_addr,
        remote_port=remote_port,
        state=state,
        state_name=state_name,
        tx_queue=tx_queue,
        rx_queue=rx_queue,
        timer_pending=timer_pending,
        timer_jiffies=timer_jiffies,
        timer_name=timer_name,
        retransmissions=retrans,
        uid=uid,
        timeout=timeout,
        inode=inode,
        raw_line=line,
    )


def parse_proc_net_tcp_text(text: str, ipv6: bool = False) -> List[ConnectionEntry]:
    """Parse the textual contents of /proc/net/tcp or /proc/net/tcp6."""
    entries: List[ConnectionEntry] = []
    for i, line in enumerate(text.splitlines()):
        entry = _parse_line(line, i, ipv6)
        if entry is not None:
            entries.append(entry)
    return entries


def parse_proc_net_tcp(path: str = "/proc/net/tcp") -> List[ConnectionEntry]:
    """Read and parse /proc/net/tcp from the given path."""
    with open(path, "r", encoding="ascii") as f:
        return parse_proc_net_tcp_text(f.read(), ipv6=False)


def parse_proc_net_tcp6(path: str = "/proc/net/tcp6") -> List[ConnectionEntry]:
    """Read and parse /proc/net/tcp6 from the given path."""
    with open(path, "r", encoding="ascii") as f:
        return parse_proc_net_tcp_text(f.read(), ipv6=True)
