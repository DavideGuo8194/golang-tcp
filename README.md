# golang-tcp

Parses `/proc/net/tcp` and `/proc/net/tcp6` into structured records with decoded state names and timer fields.

```python
from golang_tcp import parse_proc_net_tcp, parse_proc_net_tcp6, TcpState

for entry in parse_proc_net_tcp():
    print(entry.local_address, entry.local_port, entry.state_name, entry.timer_name)

for entry in parse_proc_net_tcp6():
    print(entry.local_address, entry.local_port, entry.state_name)
```

Each call returns a list of `ConnectionEntry` dataclasses with fields for local and remote address/port, decoded `state` (a `TcpState` enum) and `state_name`, send/receive queue depths, a decoded timer (`timer_pending`, `timer_jiffies`, `timer_name`, `retransmissions`), UID, timeout, inode, and the raw source line.

The library exists because reading `/proc/net/tcp` by hand is error-prone: the timer field packs a pending bit, a jiffies count, a timer-type selector, and a retransmission counter into a single hex word, and the state column is a hex code that has to be mapped back to a human name. Doing this inline in monitoring scripts leads to silent miscategorisation. This library does the decode once and returns typed records.

The IPv6 address form is returned as fully-expanded 16-bit hex groups (e.g. `0000:0000:0000:0000:0000:0000:0000:0001`), not RFC 5952 compressed form. Compressing it is out of scope; callers who need that should pass the string through the standard library's `ipaddress` module.

If the kernel reports a state code this library does not model, `state_name` becomes `UNKNOWN_<hex>` and `state` falls back to `TcpState.CLOSE` so the record is still surfaced rather than dropped. Malformed lines are skipped rather than aborting the whole parse.
