"""Wireshark MCP server.

Exposes a small set of read/analysis tools and a bounded live-capture tool,
all wrapping the locally installed tshark/dumpcap/editcap/capinfos binaries.
"""
from __future__ import annotations

import atexit
import asyncio
from contextlib import asynccontextmanager
import grp
import json
import logging
import os
import re
import secrets
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import anyio
import anyio.lowlevel
import mcp.types as mcp_types
from mcp.server.fastmcp import FastMCP
from mcp.shared.message import SessionMessage

from wireshark_mcp.runner import (
    ToolError,
    _resolve_binary,
    ensure_capture_dir,
    run,
    safe_input_path,
    safe_output_path,
)

CAPTURE_MAX_PACKETS = 100_000
CAPTURE_MAX_SECONDS = 300
LIVE_TAIL_MAX_DURATION = 3600

DISSECTOR_DIR = Path(
    os.environ.get("WIRESHARK_MCP_DISSECTOR_DIR")
    or Path.home() / ".wireshark-mcp" / "dissectors"
).resolve()

_LOADED_DISSECTORS: set[str] = set()
_TAILS: dict[str, dict[str, Any]] = {}
_TAILS_LOCK = threading.Lock()

mcp = FastMCP("wireshark")


def _ensure_dissector_dir() -> Path:
    DISSECTOR_DIR.mkdir(parents=True, exist_ok=True)
    return DISSECTOR_DIR


def _safe_dissector_path(name: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.lua", name):
        raise ToolError("dissector name must match '[A-Za-z0-9_.-]+.lua'")
    base = _ensure_dissector_dir()
    target = (base / name).resolve()
    if base not in target.parents:
        raise ToolError(f"dissector name escapes sandbox: {name}")
    return target


def _lua_args() -> list[str]:
    """tshark args that load every currently registered Lua dissector."""
    base = _ensure_dissector_dir()
    out: list[str] = []
    for name in sorted(_LOADED_DISSECTORS):
        out += ["-X", f"lua_script:{base / name}"]
    return out


_HELP_TEXT = """# Wireshark MCP — quickstart

This server wraps locally installed Wireshark CLI tools (tshark, dumpcap,
editcap, capinfos). All writes land in a sandbox dir
(default `~/.wireshark-mcp/captures/`). All captures are bounded.

## Where to start

| If you want to… | call |
|---|---|
| see what's on the network right now | `list_interfaces` → `capture` |
| one-shot "what happened in this pcap?" | `summary` (DNS + TLS + top conversations + HTTP in one call) |
| understand an existing pcap | `pcap_info` → `protocol_hierarchy` → `conversations` |
| attribute a conversation to a local process | `socket_owners` (Linux, best-effort — only sockets still open) |
| see *when* traffic happened (time-bucketed) | `io_stat` |
| see who the client talked to over HTTPS | `tls_hellos` (SNI list per ClientHello) |
| find TCP problems (drops, retrans, RTT) | `tcp_stats` |
| see decoded packets matching a filter | `read_packets` (use `fields=` for compact tabular) |
| reassemble one TCP/UDP/TLS/HTTP stream | `follow_stream` |
| handle a protocol on a non-standard port | `decode_as` (e.g. `tcp.port==2222,ssh`) |
| save a packet range as a new pcap | `extract_range` |
| browse pcaps you've already created | `list_captures` (then read `capture://<name>` resource) |
| dump raw UDP payloads (custom protocols, games) | `udp_payloads` |
| find UDP stream indexes for `follow_stream` | `udp_streams` |
| profile UDP flows (rate, payload size, jitter) | `udp_stats` |
| quick-decode bytes without writing a dissector | `decode_payload` (Python-struct spec) |
| register a custom Lua dissector for your protocol | `write_dissector` → `load_dissector` (then any tshark tool uses it) |
| tail a live capture across multiple reads | `live_tail_start` → `live_tail_read`* → `live_tail_stop` |
| wait for the tail to fall idle (e.g. round-end submitted) | `live_tail_wait_quiet` (pass `display_filter=` on a noisy interface) |
| exclude noisy endpoints from `conversations` | pass `display_filter=` (e.g. `not (tcp.port==27020)`) |

## Filter syntax — important

Two different languages, do not mix them up:

- **`display_filter`** (used by `read_packets`, `decode_as`, `tcp_stats`,
  `follow_stream`): Wireshark display-filter syntax.
  Examples: `ip.addr == 10.0.0.5`, `tcp.port == 443 and http`,
  `dns.qry.name contains "example"`.
- **`capture_filter`** (used by `capture` only): BPF syntax (libpcap).
  Examples: `tcp port 443`, `host 10.0.0.5 and not port 22`.
  No dotted field names, no `==`.

## Tabular output trick

For `read_packets` and `decode_as`, pass `fields=[...]` to get one row per
packet with just those fields, instead of the verbose JSON dissection.
Useful fields: `frame.number`, `frame.time_relative`, `ip.src`, `ip.dst`,
`tcp.srcport`, `tcp.dstport`, `_ws.col.Protocol`, `_ws.col.Info`.

## Resource scheme

- `capture://<filename>` — returns a `capinfos` summary of the named pcap
  inside the sandbox. Discover names via `list_captures`.

## Output limits

- 5 MiB stdout cap per call (env: `WIRESHARK_MCP_MAX_OUTPUT`).
- `read_packets` / `decode_as`: `max_packets` capped at 10 000.
- `capture`: `packet_count` ≤ 100 000, `duration_seconds` ≤ 300.

If a tool errors with `Permission denied` from dumpcap, the user's shell is
not in the `wireshark` group yet — they need to log out / back in.
"""


@mcp.tool()
def help() -> str:
    """Friendly overview of every tool, recommended workflows, and filter-syntax
    pitfalls. CALL THIS FIRST if you are unfamiliar with the Wireshark MCP
    server — it tells you which tool to reach for given what the user is
    asking, and the gotchas (BPF vs display filter, sandbox path, output caps).
    """
    tools = sorted(
        t.name for t in mcp._tool_manager.list_tools() if t.name != "help"
    )
    return _HELP_TEXT + f"\n## All registered tools\n\n- " + "\n- ".join(tools) + "\n"


@mcp.resource(
    "wireshark://usage",
    description="Overview of every tool, common workflows, and filter-syntax pitfalls. Read this first if unfamiliar with the server.",
    mime_type="text/markdown",
)
def usage_resource() -> str:
    """Same content as the `help` tool, exposed as a discoverable resource."""
    tools = sorted(
        t.name for t in mcp._tool_manager.list_tools() if t.name != "help"
    )
    return _HELP_TEXT + f"\n## All registered tools\n\n- " + "\n- ".join(tools) + "\n"


@mcp.tool()
def list_interfaces() -> list[dict[str, str]]:
    """List capture-capable network interfaces visible to dumpcap."""
    res = run("tshark", ["-D"])
    interfaces = []
    for line in res.stdout.splitlines():
        # tshark -D format: "N. name (friendly name)"
        m = re.match(r"\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?", line)
        if m:
            interfaces.append(
                {"index": m.group(1), "name": m.group(2), "description": m.group(3) or ""}
            )
    return interfaces


@mcp.tool()
def capture(
    interface: str,
    packet_count: int = 1000,
    duration_seconds: int = 30,
    capture_filter: str = "",
) -> dict[str, Any]:
    """Run a bounded live capture and write it to a pcapng file in the sandbox.

    `interface` is a name from list_interfaces (e.g. 'eth0', 'wlan0').
    Both `packet_count` and `duration_seconds` act as upper bounds — capture
    stops when either is hit. `capture_filter` is a BPF expression (e.g.
    'tcp port 443'), not a Wireshark display filter.
    """
    if packet_count <= 0 or packet_count > CAPTURE_MAX_PACKETS:
        raise ToolError(f"packet_count must be in 1..{CAPTURE_MAX_PACKETS}")
    if duration_seconds <= 0 or duration_seconds > CAPTURE_MAX_SECONDS:
        raise ToolError(f"duration_seconds must be in 1..{CAPTURE_MAX_SECONDS}")

    ensure_capture_dir()
    out_path = safe_output_path(f"capture-{int(time.time())}.pcapng")

    args = [
        "-i", interface,
        "-c", str(packet_count),
        "-a", f"duration:{duration_seconds}",
        "-w", str(out_path),
        "-q",
    ]
    if capture_filter:
        args += ["-f", capture_filter]

    run("dumpcap", args, timeout=duration_seconds + 10)
    return {
        "path": str(out_path),
        "size_bytes": out_path.stat().st_size,
        **pcap_info(str(out_path)),
    }


@mcp.tool()
def pcap_info(path: str) -> dict[str, str]:
    """Summarize a pcap/pcapng file (packet count, duration, encapsulation)."""
    p = safe_input_path(path)
    res = run("capinfos", [str(p)])
    info: dict[str, str] = {}
    for line in res.stdout.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            info[key.strip()] = value.strip()
    return info


@mcp.tool()
def read_packets(
    path: str,
    display_filter: str = "",
    max_packets: int = 200,
    fields: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Read packets from a pcap, optionally filtered by a Wireshark display filter.

    When `fields` is provided (e.g. ['ip.src','ip.dst','tcp.port']), returns a
    compact tabular form. Otherwise returns full PDML-like JSON per packet.
    """
    p = safe_input_path(path)
    if max_packets <= 0 or max_packets > 10_000:
        raise ToolError("max_packets must be in 1..10000")

    # tshark `-c N` limits packets *read from the file*, not packets *matching*
    # the display filter. Combining `-c` with `-Y` silently drops matches when
    # the first match is past frame N. Drop `-c` when filtering and trim in
    # Python instead.
    args = _lua_args() + ["-r", str(p)]
    if display_filter:
        args += ["-Y", display_filter]
    else:
        args += ["-c", str(max_packets)]

    if fields:
        args += ["-T", "fields", "-E", "header=y", "-E", "separator=/t"]
        for f in fields:
            args += ["-e", f]
        res = run("tshark", args)
        rows = [r for r in res.stdout.splitlines() if r]
        if not rows:
            return []
        headers = rows[0].split("\t")
        out = [dict(zip(headers, line.split("\t"))) for line in rows[1:]]
        return out[:max_packets]

    args += ["-T", "json"]
    res = run("tshark", args)
    packets = json.loads(res.stdout or "[]")
    return packets[:max_packets]


@mcp.tool()
def protocol_hierarchy(path: str) -> str:
    """Return the protocol-hierarchy statistics for a pcap (tshark -z io,phs)."""
    p = safe_input_path(path)
    res = run("tshark", _lua_args() + ["-r", str(p), "-q", "-z", "io,phs"])
    return res.stdout


@mcp.tool()
def conversations(path: str, proto: str = "tcp", display_filter: str = "") -> str:
    """Return endpoint-pair statistics for the given proto (tcp/udp/ip/eth).

    Pass `display_filter` to exclude noisy endpoints, e.g.
    `display_filter='not (tcp.port == 27020)'` to drop a specific port,
    or `display_filter='not (ipv6.addr matches "^2a01:bc80:")'` to drop
    a specific IPv6 prefix.
    """
    if proto not in {"tcp", "udp", "ip", "ipv6", "eth"}:
        raise ToolError("proto must be one of tcp,udp,ip,ipv6,eth")
    p = safe_input_path(path)
    args = _lua_args() + ["-r", str(p), "-q", "-z", f"conv,{proto}"]
    if display_filter:
        # `-z conv` stats are computed before the single-pass `-Y` filter
        # applies, so a plain `-Y` is silently ignored here. Use two-pass
        # `-2 -R` (read filter) to actually restrict the stats.
        args += ["-2", "-R", display_filter]
    res = run("tshark", args)
    return res.stdout


@mcp.tool()
def follow_stream(
    path: str,
    proto: str = "tcp",
    stream_index: int = 0,
    mode: str = "ascii",
) -> str:
    """Reassemble and return a single TCP/UDP/TLS stream by index."""
    if proto not in {"tcp", "udp", "tls", "http"}:
        raise ToolError("proto must be one of tcp,udp,tls,http")
    if mode not in {"ascii", "hex", "raw", "yaml"}:
        raise ToolError("mode must be one of ascii,hex,raw,yaml")
    p = safe_input_path(path)
    res = run(
        "tshark",
        _lua_args() + ["-r", str(p), "-q", "-z", f"follow,{proto},{mode},{stream_index}"],
    )
    return res.stdout


@mcp.tool()
def extract_range(path: str, first: int, last: int) -> dict[str, Any]:
    """Carve packets `first`..`last` (1-indexed, inclusive) into a new pcap."""
    if first < 1 or last < first:
        raise ToolError("invalid range")
    p = safe_input_path(path)
    out = safe_output_path(f"extract-{p.stem}-{first}-{last}.pcapng")
    run("editcap", ["-r", str(p), str(out), f"{first}-{last}"])
    return {"path": str(out), "size_bytes": out.stat().st_size}


_DECODE_RULE = re.compile(
    r"^[a-zA-Z0-9_.]+==\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*,[a-zA-Z0-9_.+-]+$"
)


@mcp.tool()
def decode_as(
    path: str,
    rules: list[str],
    display_filter: str = "",
    max_packets: int = 200,
    fields: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Re-read a pcap forcing protocol decoding for non-standard ports.

    `rules` is a list of `tshark -d` expressions, e.g.
    ['tcp.port==2222,ssh', 'udp.port==5060,sip']. Each rule must match
    '<layer.field>==<port-or-range>,<protocol>'. Returns packets the same
    way `read_packets` does (JSON, or tabular if `fields` is provided).
    """
    p = safe_input_path(path)
    if max_packets <= 0 or max_packets > 10_000:
        raise ToolError("max_packets must be in 1..10000")
    if not rules:
        raise ToolError("provide at least one decode rule")
    for r in rules:
        if not _DECODE_RULE.match(r):
            raise ToolError(f"invalid decode rule: {r!r}")

    # Same `-c` vs `-Y` gotcha as read_packets — don't cap reads when filtering.
    args = _lua_args() + ["-r", str(p)]
    for r in rules:
        args += ["-d", r]
    if display_filter:
        args += ["-Y", display_filter]
    else:
        args += ["-c", str(max_packets)]

    if fields:
        args += ["-T", "fields", "-E", "header=y", "-E", "separator=/t"]
        for f in fields:
            args += ["-e", f]
        res = run("tshark", args)
        rows = [r for r in res.stdout.splitlines() if r]
        if not rows:
            return []
        headers = rows[0].split("\t")
        out = [dict(zip(headers, line.split("\t"))) for line in rows[1:]]
        return out[:max_packets]

    args += ["-T", "json"]
    res = run("tshark", args)
    packets = json.loads(res.stdout or "[]")
    return packets[:max_packets]


_TCP_FLAG_FIELDS = [
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.zero_window",
    "tcp.analysis.window_full",
    "tcp.analysis.out_of_order",
    "tcp.analysis.lost_segment",
    "tcp.analysis.keep_alive",
]


@mcp.tool()
def tcp_stats(path: str, display_filter: str = "") -> dict[str, Any]:
    """Summarize TCP health: retransmissions, dup-acks, zero-windows, RTT.

    Counts every `tcp.analysis.*` flag in the capture (optionally restricted
    by `display_filter`, e.g. 'ip.addr==10.0.0.5') and computes RTT
    summary statistics (min/avg/max/p50/p95) from `tcp.analysis.ack_rtt`.
    """
    p = safe_input_path(path)

    def _filter(extra: str) -> str:
        return f"({display_filter}) and ({extra})" if display_filter else extra

    flag_args = _lua_args() + [
        "-r", str(p),
        "-Y", _filter("tcp.analysis.flags"),
        "-T", "fields",
        "-E", "separator=/t",
    ]
    for f in _TCP_FLAG_FIELDS:
        flag_args += ["-e", f]
    flag_res = run("tshark", flag_args)

    flag_counts = {f.rsplit(".", 1)[-1]: 0 for f in _TCP_FLAG_FIELDS}
    flagged_rows = 0
    for line in flag_res.stdout.splitlines():
        if not line:
            continue
        flagged_rows += 1
        for field, value in zip(_TCP_FLAG_FIELDS, line.split("\t")):
            if value:
                flag_counts[field.rsplit(".", 1)[-1]] += 1

    rtt_res = run(
        "tshark",
        _lua_args() + [
            "-r", str(p),
            "-Y", _filter("tcp.analysis.ack_rtt"),
            "-T", "fields",
            "-e", "tcp.analysis.ack_rtt",
        ],
    )
    rtts: list[float] = []
    for line in rtt_res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rtts.append(float(line))
        except ValueError:
            pass

    rtt_summary: dict[str, float] = {}
    if rtts:
        rtts.sort()
        n = len(rtts)
        rtt_summary = {
            "samples": n,
            "min": rtts[0],
            "max": rtts[-1],
            "avg": sum(rtts) / n,
            "p50": rtts[n // 2],
            "p95": rtts[min(n - 1, int(n * 0.95))],
        }

    return {
        "flagged_packets": flagged_rows,
        "flag_counts": flag_counts,
        "ack_rtt_seconds": rtt_summary,
    }


@mcp.tool()
def tls_hellos(path: str, display_filter: str = "") -> list[dict[str, Any]]:
    """List every TLS ClientHello with timestamp, destination, and SNI.

    The fast way to enumerate every TLS-speaking endpoint the client opened
    without parsing PDML JSON. Useful for identifying *who* a process is
    talking to over HTTPS when you can't decrypt the payloads. `display_filter`
    is AND-ed with `tls.handshake.type == 1`.

    Returns: `[{frame, t, dst, dport, sni}, ...]`. `dst` is the destination
    IP (v4 or v6), `dport` the destination port (usually 443), `sni` the
    Server Name Indication value (may be empty if the client didn't send one).
    """
    p = safe_input_path(path)
    base = "tls.handshake.type == 1"
    flt = f"({display_filter}) and ({base})" if display_filter else base
    field_list = [
        "frame.number", "frame.time_relative",
        "ip.dst", "ipv6.dst", "tcp.dstport",
        "tls.handshake.extensions_server_name",
    ]
    args = _lua_args() + [
        "-r", str(p), "-Y", flt,
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
    ]
    for f in field_list:
        args += ["-e", f]
    res = run("tshark", args)

    out: list[dict[str, Any]] = []
    for line in res.stdout.splitlines():
        if not line:
            continue
        cols = (line.split("\t") + [""] * len(field_list))[:len(field_list)]
        n, t, ip4d, ip6d, dport, sni = cols
        out.append({
            "frame": int(n) if n else 0,
            "t": float(t) if t else 0.0,
            "dst": ip4d or ip6d,
            "dport": int(dport) if dport else 0,
            "sni": sni,
        })
    return out


_IOSTAT_FILTER_LIMIT = 8


@mcp.tool()
def io_stat(
    path: str,
    interval_seconds: float = 5.0,
    filters: list[str] | None = None,
) -> dict[str, Any]:
    """Time-bucketed packet and byte counts. The fast way to see *when*
    traffic happened (round start vs. menu vs. asset load) without dumping
    every packet.

    `interval_seconds` is the bucket width (use `0` for "whole capture as one
    bucket"). `filters` is an optional list of up to 8 Wireshark display
    filters; each produces its own COUNT+SUM column. If omitted, you get one
    column counting every packet.

    Returns:
        {
          "interval_seconds": 5.0,
          "columns": [<filter_1>, <filter_2>, ...]   # ["all"] if none given
          "buckets": [
            {"start": 0.0, "end": 5.0,
             "counts": [<filter_1_frames>, ...],
             "bytes":  [<filter_1_bytes>,  ...]},
            ...
          ],
        }
    """
    p = safe_input_path(path)
    if interval_seconds < 0:
        raise ToolError("interval_seconds must be >= 0")
    if filters is not None and len(filters) > _IOSTAT_FILTER_LIMIT:
        raise ToolError(f"at most {_IOSTAT_FILTER_LIMIT} filters")

    # tshark expects an int interval, except "0" means "whole capture".
    iv = 0 if interval_seconds == 0 else max(1, int(round(interval_seconds)))

    # tshark `io,stat` supports two extra-column forms after the interval:
    #   bare      "io,stat,N,<filter>,<filter>"  → each filter → 1 col, Frames+Bytes
    #   typed     "io,stat,N,COUNT(<field>)<filter>,..."  → typed aggregations
    # The typed form *requires* `<field>` to be a real protocol field whose
    # presence is being counted, not the literal word "frame" — passing
    # `COUNT(frame)<filter>` silently returns zeros. We use the bare form,
    # which gives Frames+Bytes per filter directly.
    if filters:
        cols = list(filters)
        z_arg = ",".join([f"io,stat,{iv}"] + cols)
    else:
        cols = ["all"]
        z_arg = f"io,stat,{iv}"

    res = run("tshark", _lua_args() + ["-r", str(p), "-q", "-z", z_arg])

    # Parse the ASCII table. Bucket lines look like:
    #   |   0 <>      5  |    113 |  127942 |  ... |
    # We extract `start`, `end`, then alternating COUNT/SUM numeric cells.
    buckets: list[dict[str, Any]] = []
    interval_re = re.compile(
        r"^\|\s*([\d.]+|Dur)?\s*<>\s*([\d.]+|Dur)\s*\|(.+)\|\s*$"
    )
    for line in res.stdout.splitlines():
        m = interval_re.match(line)
        if not m:
            continue
        start_s, end_s, rest = m.group(1), m.group(2), m.group(3)
        try:
            start = float(start_s) if start_s and start_s != "Dur" else 0.0
        except ValueError:
            continue
        end = None
        if end_s and end_s != "Dur":
            try:
                end = float(end_s)
            except ValueError:
                end = None
        cells = [c.strip() for c in rest.split("|") if c.strip()]
        nums: list[int] = []
        for c in cells:
            try:
                nums.append(int(c))
            except ValueError:
                pass
        counts = nums[0::2]
        sums = nums[1::2]
        if len(counts) < len(cols):
            continue
        buckets.append({
            "start": start,
            "end": end,
            "counts": counts[:len(cols)],
            "bytes": sums[:len(cols)],
        })

    return {
        "interval_seconds": float(iv),
        "columns": cols,
        "buckets": buckets,
    }


@mcp.tool()
def list_captures() -> list[dict[str, Any]]:
    """List pcap/pcapng files currently in the capture sandbox dir."""
    base = ensure_capture_dir()
    out = []
    for entry in sorted(base.iterdir()):
        if entry.is_file() and entry.suffix in {".pcap", ".pcapng", ".cap"}:
            st = entry.stat()
            out.append({
                "name": entry.name,
                "uri": f"capture://{entry.name}",
                "size_bytes": st.st_size,
                "mtime": st.st_mtime,
            })
    return out


@mcp.resource(
    "capture://{name}",
    description="capinfos summary of a pcap in the capture sandbox",
    mime_type="text/plain",
)
def capture_resource(name: str) -> str:
    """Return capinfos summary for a sandboxed pcap by filename."""
    base = ensure_capture_dir()
    target = (base / name).resolve()
    if base not in target.parents:
        raise ToolError(f"resource not in sandbox: {name}")
    if not target.is_file():
        raise ToolError(f"no such capture: {name}")
    return run("capinfos", [str(target)]).stdout


@mcp.tool()
def udp_payloads(
    path: str,
    display_filter: str = "",
    max_packets: int = 500,
    byte_offset: int = 0,
    byte_length: int | None = None,
) -> list[dict[str, Any]]:
    """One row per UDP packet with raw payload hex. The fast path for inspecting
    custom binary protocols (e.g. game traffic) without parsing PDML JSON.

    Returns: `[{frame, t, src, dst, len, hex}, ...]` where `src`/`dst` are
    `ip:port`, `len` is the UDP payload byte count (header stripped), and `hex`
    is the lowercase payload hex string. `display_filter` is AND-ed with `udp`.
    Use `byte_offset` + `byte_length` to slice down to a header when payloads
    are large (e.g. `byte_length=8` shows just the first 8 bytes).
    """
    p = safe_input_path(path)
    if max_packets <= 0 or max_packets > 10_000:
        raise ToolError("max_packets must be in 1..10000")
    if byte_offset < 0 or (byte_length is not None and byte_length < 0):
        raise ToolError("byte_offset and byte_length must be non-negative")

    flt = f"({display_filter}) and udp" if display_filter else "udp"
    field_list = [
        "frame.number", "frame.time_relative",
        "ip.src", "ipv6.src", "udp.srcport",
        "ip.dst", "ipv6.dst", "udp.dstport",
        "udp.length", "udp.payload",
    ]
    args = _lua_args() + [
        "-r", str(p), "-c", str(max_packets), "-Y", flt,
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
    ]
    for f in field_list:
        args += ["-e", f]
    res = run("tshark", args)

    out: list[dict[str, Any]] = []
    for line in res.stdout.splitlines():
        if not line:
            continue
        cols = (line.split("\t") + [""] * len(field_list))[:len(field_list)]
        n, t, ip4s, ip6s, sport, ip4d, ip6d, dport, ulen, payload = cols
        hex_payload = re.sub(r"[^0-9a-fA-F]", "", payload).lower()
        if byte_offset or byte_length is not None:
            start = byte_offset * 2
            end = start + byte_length * 2 if byte_length is not None else None
            hex_payload = hex_payload[start:end]
        out.append({
            "frame": int(n) if n else 0,
            "t": float(t) if t else 0.0,
            "src": f"{ip4s or ip6s}:{sport}",
            "dst": f"{ip4d or ip6d}:{dport}",
            "len": max(0, int(ulen) - 8) if ulen else 0,
            "hex": hex_payload,
        })
    return out


@mcp.tool()
def udp_streams(path: str, display_filter: str = "") -> list[dict[str, Any]]:
    """List every UDP stream with its index, endpoints, packet/byte counts, and
    timestamps. Use the `index` field with `follow_stream(proto='udp',
    stream_index=N)` to reassemble payloads of that stream.
    """
    p = safe_input_path(path)
    flt = f"({display_filter}) and udp" if display_filter else "udp"
    field_list = [
        "udp.stream",
        "ip.src", "ipv6.src", "udp.srcport",
        "ip.dst", "ipv6.dst", "udp.dstport",
        "frame.time_relative", "udp.length",
    ]
    args = _lua_args() + [
        "-r", str(p), "-Y", flt,
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
    ]
    for f in field_list:
        args += ["-e", f]
    res = run("tshark", args)

    streams: dict[int, dict[str, Any]] = {}
    for line in res.stdout.splitlines():
        if not line:
            continue
        cols = (line.split("\t") + [""] * len(field_list))[:len(field_list)]
        sid_s, ip4s, ip6s, sport, ip4d, ip6d, dport, t_s, ulen_s = cols
        try:
            sid = int(sid_s)
        except ValueError:
            continue
        try:
            ts = float(t_s)
        except ValueError:
            ts = 0.0
        payload_len = max(0, (int(ulen_s) if ulen_s else 0) - 8)

        a = (ip4s or ip6s, sport)
        b = (ip4d or ip6d, dport)
        ep_a, ep_b = sorted([a, b])

        s = streams.get(sid)
        if s is None:
            s = streams[sid] = {
                "index": sid,
                "endpoint_a": f"{ep_a[0]}:{ep_a[1]}",
                "endpoint_b": f"{ep_b[0]}:{ep_b[1]}",
                "packets": 0,
                "payload_bytes": 0,
                "first_t": ts,
                "last_t": ts,
            }
        s["packets"] += 1
        s["payload_bytes"] += payload_len
        if ts < s["first_t"]:
            s["first_t"] = ts
        if ts > s["last_t"]:
            s["last_t"] = ts

    out = []
    for s in sorted(streams.values(), key=lambda x: x["index"]):
        s["duration"] = s["last_t"] - s["first_t"]
        out.append(s)
    return out


@mcp.tool()
def write_dissector(name: str, lua_source: str) -> dict[str, Any]:
    """Save a Lua dissector under `~/.wireshark-mcp/dissectors/<name>`.

    `name` must match `[A-Za-z0-9_.-]+.lua`. Overwrites if it exists. Call
    `load_dissector(name)` to register it so subsequent tshark calls (read_packets,
    decode_as, follow_stream, udp_payloads, udp_streams, udp_stats, tcp_stats,
    protocol_hierarchy, conversations, live_tail_read) load it via
    `-X lua_script:`.
    """
    path = _safe_dissector_path(name)
    path.write_text(lua_source)
    return {"name": name, "path": str(path), "size_bytes": path.stat().st_size}


@mcp.tool()
def load_dissector(name: str) -> dict[str, Any]:
    """Register an existing dissector by filename so every tshark call uses it.

    The file must exist in the dissector dir (write it with `write_dissector`
    or drop it there manually). Errors in the Lua surface on first use.
    """
    path = _safe_dissector_path(name)
    if not path.is_file():
        raise ToolError(f"no such dissector: {name} (write it first or drop a file in {DISSECTOR_DIR})")
    _LOADED_DISSECTORS.add(name)
    return {"loaded": sorted(_LOADED_DISSECTORS), "dir": str(DISSECTOR_DIR)}


@mcp.tool()
def unload_dissector(name: str) -> dict[str, Any]:
    """Stop using a previously loaded dissector. The file is kept on disk."""
    _LOADED_DISSECTORS.discard(name)
    return {"loaded": sorted(_LOADED_DISSECTORS)}


@mcp.tool()
def list_dissectors() -> dict[str, Any]:
    """List dissector files in the sandbox dir and which are currently loaded."""
    base = _ensure_dissector_dir()
    files = sorted(p.name for p in base.iterdir() if p.suffix == ".lua")
    return {
        "dir": str(base),
        "files": files,
        "loaded": sorted(_LOADED_DISSECTORS),
    }


def _parse_struct_spec(spec: str) -> tuple[str, list[tuple[str, str]]]:
    """Parse 'BE B opcode; H seq; f x' → ('>', [('opcode','B'), ...])."""
    spec = spec.strip()
    if not spec:
        raise ToolError("empty struct spec")
    endian = "<"
    if spec[:1] in "<>!=@":
        endian, spec = spec[0], spec[1:].lstrip()
    elif spec[:3].upper() in ("BE ", "LE "):
        endian = ">" if spec[:2].upper() == "BE" else "<"
        spec = spec[3:].lstrip()
    fields: list[tuple[str, str]] = []
    for part in spec.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if len(tokens) != 2:
            raise ToolError(f"bad field spec (expected '<fmt> <name>'): {part!r}")
        fmt, fname = tokens
        try:
            struct.calcsize(endian + fmt)
        except struct.error as e:
            raise ToolError(f"bad struct format {fmt!r}: {e}") from e
        fields.append((fname, fmt))
    if not fields:
        raise ToolError("struct spec has no fields")
    return endian, fields


@mcp.tool()
def decode_payload(
    spec: str,
    hex_payload: str = "",
    path: str = "",
    frame_number: int = 0,
) -> dict[str, Any]:
    """Decode raw bytes per a Python-struct-style spec, without writing Lua.

    Provide either `hex_payload` (whitespace/colons OK) or (`path`,
    `frame_number`) to pull bytes from a pcap's UDP payload.

    Spec syntax: optional leading endian (`<`, `>`, `!`, `=`, `@`, `BE`, `LE`;
    default `<` little-endian), then `;`-separated `<fmt> <name>` pairs where
    `fmt` is a Python `struct` format (`B`, `H`, `I`, `Q`, `f`, `d`, `10s`, …).

    Example:
        decode_payload(
            spec="< B opcode; H seq; f x; f y; f z",
            hex_payload="01 0500 0000803F 00000000 0000C040",
        )
    """
    if bool(hex_payload) == bool(path):
        raise ToolError("provide exactly one of hex_payload or (path + frame_number)")

    if path:
        if frame_number < 1:
            raise ToolError("frame_number must be >= 1")
        p = safe_input_path(path)
        args = _lua_args() + [
            "-r", str(p),
            "-Y", f"frame.number == {frame_number} and udp",
            "-T", "fields",
            "-e", "udp.payload",
        ]
        res = run("tshark", args)
        line = (res.stdout.strip().splitlines() or [""])[0]
        if not line:
            raise ToolError(f"no UDP payload at frame {frame_number}")
        hex_payload = line

    cleaned = re.sub(r"[^0-9a-fA-F]", "", hex_payload)
    if len(cleaned) % 2:
        raise ToolError("hex payload has odd character count")
    raw = bytes.fromhex(cleaned)

    endian, fields = _parse_struct_spec(spec)
    offset = 0
    decoded: dict[str, Any] = {}
    for fname, fmt in fields:
        size = struct.calcsize(endian + fmt)
        if offset + size > len(raw):
            raise ToolError(
                f"payload too short at field {fname!r}: need {size} byte(s), have {len(raw) - offset}"
            )
        (value,) = struct.unpack_from(endian + fmt, raw, offset)
        if isinstance(value, bytes):
            value = value.rstrip(b"\x00").decode("utf-8", errors="replace")
        decoded[fname] = value
        offset += size

    return {
        "decoded": decoded,
        "consumed_bytes": offset,
        "remaining_bytes": len(raw) - offset,
        "remaining_hex": raw[offset:].hex(),
    }


def _shutdown_tails() -> None:
    """Terminate any still-running live captures on server exit."""
    with _TAILS_LOCK:
        handles = list(_TAILS.items())
    for _, t in handles:
        proc = t.get("proc")
        if proc and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


atexit.register(_shutdown_tails)


@mcp.tool()
def live_tail_start(
    interface: str,
    capture_filter: str = "",
    max_duration_seconds: int = 600,
    max_packets: int = 100_000,
) -> dict[str, Any]:
    """Start a background capture and return a handle for incremental reads.

    Pair with `live_tail_read(handle, ...)` to fetch packets observed since the
    last read, and `live_tail_stop(handle)` to flush and end. The capture
    self-terminates after `max_duration_seconds` (≤3600) or `max_packets`
    (≤100000), whichever comes first. The capture file lives in the sandbox so
    you can analyze it normally after stop.
    """
    if max_duration_seconds <= 0 or max_duration_seconds > LIVE_TAIL_MAX_DURATION:
        raise ToolError(f"max_duration_seconds must be in 1..{LIVE_TAIL_MAX_DURATION}")
    if max_packets <= 0 or max_packets > CAPTURE_MAX_PACKETS:
        raise ToolError(f"max_packets must be in 1..{CAPTURE_MAX_PACKETS}")

    ensure_capture_dir()
    handle = secrets.token_hex(6)
    out_path = safe_output_path(f"tail-{handle}-{int(time.time())}.pcapng")
    binary = _resolve_binary("dumpcap")

    args = [
        binary, "-i", interface, "-w", str(out_path), "-q",
        "-a", f"duration:{max_duration_seconds}",
        "-c", str(max_packets),
    ]
    if capture_filter:
        args += ["-f", capture_filter]

    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    with _TAILS_LOCK:
        _TAILS[handle] = {
            "proc": proc,
            "path": str(out_path),
            "last_frame": 0,
            "interface": interface,
            "started_at": time.time(),
        }

    return {
        "handle": handle,
        "path": str(out_path),
        "pid": proc.pid,
        "interface": interface,
    }


@mcp.tool()
def live_tail_read(
    handle: str,
    display_filter: str = "",
    max_packets: int = 200,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Fetch packets seen since the last read on this handle.

    Same `display_filter` / `fields` semantics as `read_packets`. Returns
    `{packets, last_frame, alive}`. `alive=false` means dumpcap has exited
    (duration/packet cap hit, or someone stopped it explicitly).
    """
    if max_packets <= 0 or max_packets > 10_000:
        raise ToolError("max_packets must be in 1..10000")
    with _TAILS_LOCK:
        t = _TAILS.get(handle)
    if not t:
        raise ToolError(f"unknown tail handle: {handle}")

    tail_path = Path(t["path"])
    alive = t["proc"].poll() is None

    if not tail_path.exists() or tail_path.stat().st_size < 32:
        return {"packets": [], "last_frame": t["last_frame"], "alive": alive}

    last = t["last_frame"]
    new_filter = f"frame.number > {last}"
    full_filter = f"({display_filter}) and ({new_filter})" if display_filter else new_filter

    # No `-c` here: tshark applies `-c` to packets read, not packets matching,
    # so combining it with `-Y` would silently miss matches past the first N
    # frames in the file. We trim the result list in Python below.
    base_args = _lua_args() + [
        "-r", str(tail_path), "-Y", full_filter,
    ]

    if fields:
        user_fields = list(fields)
        added_frame = "frame.number" not in user_fields
        internal_fields = (["frame.number"] + user_fields) if added_frame else user_fields

        args = base_args + ["-T", "fields", "-E", "header=y", "-E", "separator=/t"]
        for f in internal_fields:
            args += ["-e", f]
        res = run("tshark", args)
        rows = [r for r in res.stdout.splitlines() if r]
        if not rows:
            packets: list[dict[str, Any]] = []
        else:
            headers = rows[0].split("\t")
            packets = [dict(zip(headers, line.split("\t"))) for line in rows[1:]]
        packets = packets[:max_packets]
        max_f = last
        for pkt in packets:
            try:
                n = int(pkt.get("frame.number", "0") or 0)
                if n > max_f:
                    max_f = n
            except (ValueError, TypeError):
                pass
        if added_frame:
            for pkt in packets:
                pkt.pop("frame.number", None)
    else:
        res = run("tshark", base_args + ["-T", "json"])
        packets = json.loads(res.stdout or "[]")
        packets = packets[:max_packets]
        max_f = last
        for pkt in packets:
            try:
                n = int(pkt["_source"]["layers"]["frame"]["frame.number"])
                if n > max_f:
                    max_f = n
            except (KeyError, ValueError, TypeError):
                pass

    with _TAILS_LOCK:
        if handle in _TAILS:
            _TAILS[handle]["last_frame"] = max_f

    return {"packets": packets, "last_frame": max_f, "alive": alive}


@mcp.tool()
def live_tail_wait_quiet(
    handle: str,
    quiet_seconds: float = 5.0,
    max_wait_seconds: float = 120.0,
    poll_interval_seconds: float = 0.5,
    display_filter: str = "",
) -> dict[str, Any]:
    """Block until the live capture has been idle for `quiet_seconds`, then
    return. Lets you reliably wait for a logical event (e.g. round-end
    submission) to complete without guessing how long it takes or stopping
    too early.

    Activity signal:
    - Default (no `display_filter`): the capture file's size on disk. Cheap
      but counts ALL traffic — useless on a busy interface where unrelated
      flows keep the file growing.
    - With `display_filter`: counts only packets matching the filter using
      tshark. Use this to wait for a specific conversation to fall idle
      while ignoring background noise (e.g.
      `display_filter='tls.handshake.extensions_server_name contains "example.com"'`
      or `display_filter='ip.addr == 1.2.3.4'`). Each poll runs tshark, so
      pick a `poll_interval_seconds` ≥ 2 for non-trivial captures.

    Returns when:
    - signal hasn't moved for `quiet_seconds` (`reason="quiet"`), OR
    - `max_wait_seconds` elapses (`reason="timeout"`), OR
    - dumpcap exits (`reason="exited"`).

    Returns: {reason, waited_seconds, last_size_bytes, alive,
              matched_packets (if display_filter)}.

    Typical workflow:
        live_tail_start(...)
        # ...user does the thing...
        live_tail_wait_quiet(handle, quiet_seconds=5,
                             display_filter='ip.addr == 1.2.3.4')
        live_tail_stop(handle)
    """
    if quiet_seconds <= 0 or max_wait_seconds <= 0 or poll_interval_seconds <= 0:
        raise ToolError("seconds parameters must be > 0")
    if poll_interval_seconds > quiet_seconds:
        raise ToolError("poll_interval_seconds must be <= quiet_seconds")
    if max_wait_seconds > LIVE_TAIL_MAX_DURATION:
        raise ToolError(f"max_wait_seconds must be <= {LIVE_TAIL_MAX_DURATION}")

    with _TAILS_LOCK:
        t = _TAILS.get(handle)
    if not t:
        raise ToolError(f"unknown tail handle: {handle}")
    tail_path = Path(t["path"])

    def _count_matches() -> int:
        """Count filter-matching packets in the live capture file. Returns 0
        if the file is too small / unreadable rather than raising — we treat
        an unreadable poll as "no new activity"."""
        if not tail_path.exists() or tail_path.stat().st_size < 32:
            return 0
        try:
            res = run(
                "tshark",
                _lua_args() + [
                    "-r", str(tail_path), "-Y", display_filter,
                    "-T", "fields", "-e", "frame.number",
                ],
                timeout=max(10, int(poll_interval_seconds * 4)),
            )
        except ToolError:
            return 0
        return sum(1 for ln in res.stdout.splitlines() if ln.strip())

    use_filter = bool(display_filter)
    started = time.monotonic()
    last_size = tail_path.stat().st_size if tail_path.exists() else 0
    last_count = _count_matches() if use_filter else 0
    last_change = started

    while True:
        time.sleep(poll_interval_seconds)
        now = time.monotonic()
        waited = now - started
        size = tail_path.stat().st_size if tail_path.exists() else 0
        alive = t["proc"].poll() is None

        if use_filter:
            count = _count_matches()
            if count != last_count:
                last_count = count
                last_change = now
        else:
            if size != last_size:
                last_size = size
                last_change = now

        if not alive:
            out: dict[str, Any] = {
                "reason": "exited", "waited_seconds": waited,
                "last_size_bytes": size, "alive": False,
            }
            if use_filter:
                out["matched_packets"] = last_count
            return out
        if now - last_change >= quiet_seconds:
            out = {
                "reason": "quiet", "waited_seconds": waited,
                "last_size_bytes": size, "alive": True,
            }
            if use_filter:
                out["matched_packets"] = last_count
            return out
        if waited >= max_wait_seconds:
            out = {
                "reason": "timeout", "waited_seconds": waited,
                "last_size_bytes": size, "alive": True,
            }
            if use_filter:
                out["matched_packets"] = last_count
            return out


@mcp.tool()
def live_tail_stop(handle: str) -> dict[str, Any]:
    """Flush, terminate, and remove a tail. Returns the final capture file info."""
    with _TAILS_LOCK:
        t = _TAILS.pop(handle, None)
    if not t:
        raise ToolError(f"unknown tail handle: {handle}")
    proc = t["proc"]
    if proc.poll() is None:
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass

    path = Path(t["path"])
    size = path.stat().st_size if path.exists() else 0
    return {
        "path": str(path),
        "size_bytes": size,
        "last_frame_seen": t["last_frame"],
        "exit_code": proc.returncode,
    }


# --- mitmproxy integration -------------------------------------------------
#
# Wraps mitmweb (mitmproxy >= 10) running in process-local eBPF mode so an
# LLM can spawn a TLS interception session, inspect decrypted flows, and tear
# it down. This is the generic abstraction: the MCP knows nothing about which
# app is being inspected. For apps whose TLS stack ignores the OS trust
# store (some game engines, some language runtimes), additional CA-override
# steps live in the per-project setup, not here.

import http.cookiejar
import io as _io
import tempfile
import urllib.error
import urllib.request

_MITMS: dict[str, dict[str, Any]] = {}
_MITMS_LOCK = threading.Lock()
_MITM_TOKEN_RE = re.compile(
    r"http://127\.0\.0\.1:(?P<port>\d+)/\?token=(?P<token>[0-9a-fA-F]+)"
)


def _unlink_quiet(path: str | None) -> None:
    if not path:
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _shutdown_mitms() -> None:
    """Terminate any still-running mitm sessions on server exit."""
    with _MITMS_LOCK:
        items = list(_MITMS.items())
    for _, m in items:
        proc = m.get("proc")
        if proc and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        _unlink_quiet(m.get("stream_path"))


atexit.register(_shutdown_mitms)


def _mitm_get(m: dict[str, Any], path: str, timeout: float = 10.0) -> bytes:
    """Authenticated GET against the mitm web API. Raises ToolError on non-2xx."""
    url = f"http://127.0.0.1:{m['port']}{path}"
    opener: urllib.request.OpenerDirector = m["opener"]
    try:
        with opener.open(url, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        raise ToolError(f"mitm api {e.code} {path}: {e.reason}")
    except urllib.error.URLError as e:
        raise ToolError(f"mitm api unreachable ({path}): {e.reason}")


@mcp.tool()
def mitm_start(
    process_name: str,
    web_port: int = 8081,
    startup_timeout_seconds: float = 15.0,
) -> dict[str, Any]:
    """Start mitmproxy in process-local mode against a binary name; return a handle.

    Uses mitmproxy's `mode local:<process>` (eBPF-based) so only the named
    binary's connections are intercepted — the rest of the host is untouched,
    including this MCP server. Returns a handle, the authenticated `web_url`
    (open it in a browser to see decrypted flows live), and the eBPF
    redirector PID.

    Prerequisites:
    - `mitmweb` on PATH (mitmproxy >= 10). The Ubuntu/Debian package is
      typically too old; use `pipx install mitmproxy`.
    - Passwordless `sudo` for the redirector. mitmweb spawns
      `mitmproxy-linux-redirector` via `sudo`; if your sudoers needs a
      password, run `sudo true` once in the same terminal first, or grant
      a NOPASSWD rule.
    - Linux kernel >= 5.7 (for the eBPF features the redirector uses).

    TLS interception requires the target app to trust mitmproxy's CA cert
    (`~/.mitmproxy/mitmproxy-ca-cert.pem`). Apps that read the OS trust
    store work after `sudo update-ca-certificates`. Apps that ignore it
    (some game engines, sandboxed runtimes) need an engine-specific
    CA-override; that setup is per-project, not handled by this tool.

    Pair with `mitm_flows(handle)` to list captured flows and
    `mitm_flow_body(handle, flow_id, direction)` to dump a request or
    response body. `mitm_stop(handle)` ends the session.
    """
    if not re.fullmatch(r"[A-Za-z0-9_.+\-]{1,128}", process_name):
        raise ToolError("process_name must be a plain binary basename (1..128 chars)")
    if not (1024 <= web_port <= 65535):
        raise ToolError("web_port must be in 1024..65535")
    if startup_timeout_seconds <= 0 or startup_timeout_seconds > 120:
        raise ToolError("startup_timeout_seconds must be in (0, 120]")

    mitmweb_bin = shutil.which("mitmweb")
    if not mitmweb_bin:
        raise ToolError(
            "mitmweb not found on PATH. Install with: pipx install mitmproxy"
        )

    # Per-session flow stream file. mitmweb appends serialized flows here as
    # they complete (including WebSocket messages, which the web REST API
    # doesn't expose). `mitm_ws_messages` reads it back. We create the file
    # with mkstemp so it's owned by us with sane perms.
    stream_fd, stream_path = tempfile.mkstemp(prefix="wireshark-mcp-mitm-", suffix=".flows")
    os.close(stream_fd)

    args = [
        mitmweb_bin,
        "--mode", f"local:{process_name}",
        "--no-web-open-browser",
        "--web-port", str(web_port),
        "--save-stream-file", stream_path,
    ]

    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    # Read interleaved stdout/stderr until we see the token URL, mitm exits,
    # or we time out. Anything we read goes into `captured` so the user can
    # see what went wrong.
    captured: list[str] = []
    token: str | None = None
    port: int = web_port
    sudo_password_required: bool = False
    deadline = time.time() + startup_timeout_seconds
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05)
            continue
        captured.append(line)
        # The eBPF redirector is spawned via `sudo`. If the user's sudoers
        # config needs a password, sudo prints one of these patterns to
        # stderr and then blocks on stdin forever — bail out with a useful
        # hint instead of waiting for the generic timeout.
        if (
            "sudo: a password is required" in line
            or "a terminal is required to read the password" in line
            or "[sudo] password for" in line
        ):
            sudo_password_required = True
            break
        match = _MITM_TOKEN_RE.search(line)
        if match:
            token = match.group("token")
            port = int(match.group("port"))
            break

    if token is None:
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        _unlink_quiet(stream_path)
        if sudo_password_required:
            raise ToolError(
                "mitmweb's eBPF redirector needs passwordless `sudo`, but "
                "your sudoers config is prompting for a password. Fix one "
                "of:\n"
                "  • run `sudo true` once in any terminal under the same "
                "user (caches credentials for ~15 min), then retry; or\n"
                "  • add a NOPASSWD rule for mitmproxy-linux-redirector, "
                "e.g. in `sudo visudo`:\n"
                f"      {os.environ.get('USER', '<user>')} ALL=(root) "
                "NOPASSWD: /path/to/mitmproxy-linux-redirector\n"
                "    (find the path with `find ~/.local ~/.mitmproxy "
                "/usr -name mitmproxy-linux-redirector 2>/dev/null`).\n\n"
                "Last mitm output:\n"
                + "".join(captured)[-2000:]
            )
        raise ToolError(
            "mitmweb did not emit a token URL within "
            f"{startup_timeout_seconds:.0f}s. Last output:\n"
            + "".join(captured)[-2000:]
        )

    # Drain remaining stdout in the background so the OS pipe buffer doesn't
    # fill up and stall the process.
    def _drain() -> None:
        try:
            for line in iter(proc.stdout.readline, ""):
                captured.append(line)
                if len(captured) > 2000:
                    del captured[:1000]
        except Exception:
            pass

    threading.Thread(target=_drain, daemon=True).start()

    # Prime auth: GET /?token=... once to receive the session cookie. Reuse
    # the same opener for all subsequent requests on this handle.
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    auth_url = f"http://127.0.0.1:{port}/?token={token}"
    try:
        with opener.open(auth_url, timeout=5) as resp:
            _ = resp.read()
    except Exception as e:
        proc.kill()
        _unlink_quiet(stream_path)
        raise ToolError(f"failed to authenticate against mitmweb at {auth_url}: {e}")

    handle = secrets.token_hex(6)
    with _MITMS_LOCK:
        _MITMS[handle] = {
            "proc": proc,
            "port": port,
            "token": token,
            "process_name": process_name,
            "started_at": time.time(),
            "output": captured,
            "opener": opener,
            "stream_path": stream_path,
        }

    return {
        "handle": handle,
        "web_url": auth_url,
        "web_port": port,
        "process_name": process_name,
        "pid": proc.pid,
        "ca_cert_path": str(Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"),
        "note": (
            "Open web_url in a browser to inspect flows live. If the target "
            "app rejects mitm's cert with 'Unknown CA', its TLS stack ignores "
            "the OS trust store; configure the engine-specific CA override "
            "and relaunch the app."
        ),
    }


@mcp.tool()
def mitm_flows(
    handle: str,
    host_contains: str = "",
    flow_type: str = "",
    limit: int = 100,
) -> dict[str, Any]:
    """List flows captured by a running mitm session, newest first.

    Returns one summary row per flow with minimal fields (id, type, host,
    method, status, byte counts, ws message count). Use `mitm_flow_body` to
    fetch a single flow's request/response body once you've picked the
    interesting `flow_id`.

    Filters:
    - `host_contains`: case-insensitive substring match on the HTTP host.
      Non-HTTP flows are dropped when this is set.
    - `flow_type`: one of `http`, `tcp`, `udp`, `dns` to restrict to that
      type. Empty means all types.
    - `limit`: cap of returned summaries (1..500).
    """
    if limit <= 0 or limit > 500:
        raise ToolError("limit must be in 1..500")
    if flow_type and flow_type not in ("http", "tcp", "udp", "dns"):
        raise ToolError("flow_type must be one of: http, tcp, udp, dns")

    with _MITMS_LOCK:
        m = _MITMS.get(handle)
    if not m:
        raise ToolError(f"unknown mitm handle: {handle}")

    raw = _mitm_get(m, "/flows")
    try:
        flows = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ToolError(f"mitm /flows returned non-JSON: {e}")

    summaries: list[dict[str, Any]] = []
    for f in flows:
        ftype = f.get("type")
        if flow_type and ftype != flow_type:
            continue
        if ftype == "http":
            req = f.get("request") or {}
            host = req.get("pretty_host", "") or req.get("host", "")
            if host_contains and host_contains.lower() not in host.lower():
                continue
            res = f.get("response") or {}
            ws = f.get("websocket") or {}
            ws_meta = ws.get("messages_meta") if isinstance(ws, dict) else None
            ws_meta = ws_meta or {}
            summaries.append({
                "flow_id": f.get("id"),
                "type": ftype,
                "ts": f.get("timestamp_created"),
                "method": req.get("method"),
                "scheme": req.get("scheme"),
                "host": host,
                "path": req.get("path"),
                "status": res.get("status_code"),
                "req_bytes": req.get("contentLength"),
                "res_bytes": res.get("contentLength"),
                "ws_msg_count": ws_meta.get("count", 0),
                "ws_bytes": ws_meta.get("contentLength", 0),
                "ws_closed": (ws or {}).get("timestamp_end") is not None,
            })
        else:
            if host_contains:
                continue
            cc = f.get("client_conn") or {}
            sc = f.get("server_conn") or {}
            summaries.append({
                "flow_id": f.get("id"),
                "type": ftype,
                "ts": f.get("timestamp_created"),
                "client": cc.get("peername"),
                "server": sc.get("address"),
            })

    summaries.sort(key=lambda x: x.get("ts") or 0, reverse=True)
    return {
        "flows": summaries[:limit],
        "returned": min(len(summaries), limit),
        "total_in_mitm": len(flows),
    }


@mcp.tool()
def mitm_flow_body(
    handle: str,
    flow_id: str,
    direction: str,
    max_bytes: int = 65536,
) -> dict[str, Any]:
    """Fetch the raw request or response body of a single HTTP flow.

    `direction` is `request` or `response`. Returns the body as utf-8 text
    when it decodes cleanly, otherwise as a lowercase hex string with
    `encoding: 'hex'`. Truncated to `max_bytes` (default 64 KiB; cap 4 MiB).

    For WebSocket flows the body endpoints return the HTTP/1.1 upgrade
    request/response, not the WebSocket frames themselves. Use
    `mitm_ws_messages(handle, flow_id)` to read individual decrypted
    WebSocket message frames.
    """
    if direction not in ("request", "response"):
        raise ToolError("direction must be 'request' or 'response'")
    if not re.fullmatch(r"[0-9a-fA-F-]{8,64}", flow_id):
        raise ToolError("flow_id looks malformed (expected UUID-ish)")
    if max_bytes <= 0 or max_bytes > 4_000_000:
        raise ToolError("max_bytes must be in 1..4000000")

    with _MITMS_LOCK:
        m = _MITMS.get(handle)
    if not m:
        raise ToolError(f"unknown mitm handle: {handle}")

    raw = _mitm_get(m, f"/flows/{flow_id}/{direction}/content.data")
    truncated = len(raw) > max_bytes
    blob = raw[:max_bytes]
    try:
        text = blob.decode("utf-8")
        return {
            "flow_id": flow_id,
            "direction": direction,
            "body": text,
            "encoding": "utf-8",
            "total_bytes": len(raw),
            "truncated": truncated,
        }
    except UnicodeDecodeError:
        return {
            "flow_id": flow_id,
            "direction": direction,
            "body": blob.hex(),
            "encoding": "hex",
            "total_bytes": len(raw),
            "truncated": truncated,
        }


@mcp.tool()
def mitm_ws_messages(
    handle: str,
    flow_id: str,
    limit: int = 100,
    max_bytes_per_message: int = 8192,
    offset: int = 0,
) -> dict[str, Any]:
    """Return decrypted WebSocket message frames for a single flow.

    mitmweb's REST API does not expose individual WebSocket frames; this
    tool reads them from the session's on-disk flow stream file (written
    via `--save-stream-file` since `mitm_start`). Each returned message
    has its direction, opcode (`text`/`binary`/other), timestamp, byte
    length, and content. Text messages are returned as utf-8 strings;
    binary messages as a lowercase hex string with `encoding: 'hex'`.

    Messages longer than `max_bytes_per_message` are truncated (the full
    `total_bytes` is still reported). `offset` and `limit` page through
    the message list in arrival order; the total count of messages on
    the flow is returned as `total_messages`.

    Note: the flow stream file is updated when mitmproxy considers a
    flow "done" enough to serialize (e.g. on close or periodically). A
    long-lived WebSocket may not appear in this output until it closes
    or the next flush. If you don't see frames yet, give the connection
    a moment and retry, or close it (e.g. quit the app).
    """
    if not re.fullmatch(r"[0-9a-fA-F-]{8,64}", flow_id):
        raise ToolError("flow_id looks malformed (expected UUID-ish)")
    if limit <= 0 or limit > 1000:
        raise ToolError("limit must be in 1..1000")
    if max_bytes_per_message <= 0 or max_bytes_per_message > 1_000_000:
        raise ToolError("max_bytes_per_message must be in 1..1000000")
    if offset < 0:
        raise ToolError("offset must be >= 0")

    with _MITMS_LOCK:
        m = _MITMS.get(handle)
    if not m:
        raise ToolError(f"unknown mitm handle: {handle}")

    stream_path = m.get("stream_path")
    if not stream_path or not os.path.exists(stream_path):
        raise ToolError(
            "no flow stream file for this handle — restart mitm_start "
            "(this handle predates --save-stream-file support)"
        )

    # Import lazily so import-time of the server isn't dragged by mitmproxy.
    try:
        from mitmproxy import io as mitm_io
        from mitmproxy.exceptions import FlowReadException
    except ImportError as e:
        raise ToolError(
            f"mitmproxy library not importable: {e}. Re-run install.sh "
            "to install the new dependency."
        )

    # Snapshot the file so a concurrent mitmweb write doesn't tear our read.
    try:
        with open(stream_path, "rb") as f:
            snapshot = f.read()
    except OSError as e:
        raise ToolError(f"failed to read flow stream file: {e}")

    if not snapshot:
        return {
            "flow_id": flow_id,
            "messages": [],
            "total_messages": 0,
            "returned": 0,
            "offset": offset,
            "note": (
                "Stream file is empty. mitmproxy only writes flows once they "
                "are considered complete — for a live WebSocket, close it "
                "first (e.g. quit the app)."
            ),
        }

    target = None
    try:
        for flow in mitm_io.FlowReader(_io.BytesIO(snapshot)).stream():
            if flow.id == flow_id:
                target = flow
                # don't break — last serialization of a given id is freshest
    except FlowReadException as e:
        # Truncated final record is expected during live capture; if we
        # already found our flow we just use it.
        if target is None:
            raise ToolError(f"flow stream file is unreadable: {e}")

    if target is None:
        return {
            "flow_id": flow_id,
            "messages": [],
            "total_messages": 0,
            "returned": 0,
            "offset": offset,
            "note": (
                "flow not found in stream file yet — mitmproxy only flushes "
                "flows once they close. If the WebSocket is still open, "
                "wait for it to end (or close the app) and retry."
            ),
        }

    ws_data = getattr(target, "websocket", None)
    if ws_data is None:
        raise ToolError(f"flow {flow_id} is not a WebSocket flow")

    all_msgs = list(ws_data.messages or [])
    total = len(all_msgs)
    page = all_msgs[offset : offset + limit]

    out: list[dict[str, Any]] = []
    for msg in page:
        opcode_name = getattr(getattr(msg, "type", None), "name", str(msg.type)).lower()
        content: bytes = msg.content or b""
        total_bytes = len(content)
        blob = content[:max_bytes_per_message]
        truncated = total_bytes > max_bytes_per_message
        is_text = bool(getattr(msg, "is_text", opcode_name == "text"))
        if is_text:
            try:
                body = blob.decode("utf-8")
                encoding = "utf-8"
            except UnicodeDecodeError:
                body = blob.hex()
                encoding = "hex"
        else:
            body = blob.hex()
            encoding = "hex"
        out.append({
            "from_client": bool(msg.from_client),
            "direction": "client->server" if msg.from_client else "server->client",
            "opcode": opcode_name,
            "ts": getattr(msg, "timestamp", None),
            "total_bytes": total_bytes,
            "truncated": truncated,
            "encoding": encoding,
            "content": body,
            "dropped": bool(getattr(msg, "dropped", False)),
            "injected": bool(getattr(msg, "injected", False)),
        })

    closed = getattr(ws_data, "timestamp_end", None) is not None
    return {
        "flow_id": flow_id,
        "messages": out,
        "total_messages": total,
        "returned": len(out),
        "offset": offset,
        "ws_closed": closed,
    }


@mcp.tool()
def mitm_stop(handle: str) -> dict[str, Any]:
    """Terminate a mitm session and forget the handle.

    Returns the final exit code and the tail of mitm's captured stdout
    (handy for debugging if something went wrong mid-session).
    """
    with _MITMS_LOCK:
        m = _MITMS.pop(handle, None)
    if not m:
        raise ToolError(f"unknown mitm handle: {handle}")
    proc = m["proc"]
    if proc.poll() is None:
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
    tail = "".join(m.get("output", []))[-2000:]
    _unlink_quiet(m.get("stream_path"))
    return {
        "process_name": m["process_name"],
        "exit_code": proc.returncode,
        "ran_for_seconds": time.time() - m["started_at"],
        "output_tail": tail,
    }


@mcp.tool()
def udp_stats(path: str, display_filter: str = "") -> dict[str, Any]:
    """Per-flow UDP rate, payload-size, and inter-arrival jitter statistics.

    Groups by (udp.stream, src→dst direction) so a bidirectional flow yields
    two rows. For each flow: `packets`, `payload_bytes`, `duration`,
    `packets_per_sec`, `bytes_per_sec`, `payload_size` summary
    (min/avg/max/p50/p95 bytes) and `inter_arrival_sec` summary
    (min/avg/max/p50/p95 seconds). `display_filter` is AND-ed with `udp`.
    """
    p = safe_input_path(path)
    flt = f"({display_filter}) and udp" if display_filter else "udp"
    field_list = [
        "udp.stream", "frame.time_relative", "udp.length",
        "ip.src", "ipv6.src", "udp.srcport",
        "ip.dst", "ipv6.dst", "udp.dstport",
    ]
    args = _lua_args() + [
        "-r", str(p), "-Y", flt,
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
    ]
    for f in field_list:
        args += ["-e", f]
    res = run("tshark", args)

    flows: dict[tuple[int, str, str], dict[str, Any]] = {}
    for line in res.stdout.splitlines():
        if not line:
            continue
        cols = (line.split("\t") + [""] * len(field_list))[:len(field_list)]
        sid_s, t_s, ulen_s, ip4s, ip6s, sport, ip4d, ip6d, dport = cols
        try:
            sid = int(sid_s)
            ts = float(t_s)
        except ValueError:
            continue
        try:
            ulen = int(ulen_s) if ulen_s else 0
        except ValueError:
            ulen = 0
        payload_len = max(0, ulen - 8)
        src = f"{ip4s or ip6s}:{sport}"
        dst = f"{ip4d or ip6d}:{dport}"

        key = (sid, src, dst)
        f = flows.get(key)
        if f is None:
            f = flows[key] = {
                "stream": sid,
                "src": src,
                "dst": dst,
                "packets": 0,
                "payload_bytes": 0,
                "first_t": ts,
                "last_t": ts,
                "_times": [],
                "_sizes": [],
            }
        f["packets"] += 1
        f["payload_bytes"] += payload_len
        if ts < f["first_t"]:
            f["first_t"] = ts
        if ts > f["last_t"]:
            f["last_t"] = ts
        f["_times"].append(ts)
        f["_sizes"].append(payload_len)

    def _summary(values: list[float]) -> dict[str, float]:
        if not values:
            return {}
        v = sorted(values)
        n = len(v)
        return {
            "samples": n,
            "min": v[0],
            "max": v[-1],
            "avg": sum(v) / n,
            "p50": v[n // 2],
            "p95": v[min(n - 1, int(n * 0.95))],
        }

    out_flows = []
    for f in sorted(flows.values(), key=lambda x: (x["stream"], x["src"])):
        times = sorted(f.pop("_times"))
        sizes = f.pop("_sizes")
        duration = f["last_t"] - f["first_t"]
        iats = [j - i for i, j in zip(times, times[1:])] if len(times) > 1 else []
        f["duration"] = duration
        f["packets_per_sec"] = (f["packets"] / duration) if duration > 0 else 0.0
        f["bytes_per_sec"] = (f["payload_bytes"] / duration) if duration > 0 else 0.0
        f["payload_size"] = _summary(sizes)
        f["inter_arrival_sec"] = _summary(iats)
        out_flows.append(f)

    return {"flows": out_flows, "flow_count": len(out_flows)}


# --- one-shot capture summary ---------------------------------------------
#
# Collapse the DNS + TLS + conversations + HTTP picture into a single tool
# call. Reduces the 3-4 round-trips an LLM otherwise needs to answer
# "what happened in this pcap?".

@mcp.tool()
def summary(
    path: str,
    host_filter: str = "",
    top_n: int = 20,
) -> dict[str, Any]:
    """One-shot rollup: DNS resolutions, TLS endpoints (by SNI), top TCP+UDP
    conversations, and any cleartext HTTP requests. The fast path for "what
    happened in this pcap?" — replaces 3-4 separate tool calls.

    `host_filter`: case-insensitive substring; when set, drops DNS rows whose
    queried name doesn't contain it, TLS rows whose SNI doesn't contain it,
    and HTTP rows whose host doesn't contain it. Conversation rows are
    filtered by whether either endpoint's IP appeared in any kept DNS/TLS
    row (so you can narrow to "everything to/from this host").

    `top_n` caps each section's list length (default 20, max 200).

    Returns:
      {
        "pcap": {capinfos summary fields...},
        "dns": [{name, ips, cnames}, ...],            # one per unique name
        "tls": [{sni, dst, dport, hellos, first_t}, ...],  # one per SNI:dst
        "conversations": {
          "tcp": [{a, b, frames_a_to_b, bytes_a_to_b,
                   frames_b_to_a, bytes_b_to_a, duration}, ...],
          "udp": [{...}, ...],
        },
        "http_requests": [{t, host, method, uri, status, resp_bytes}, ...],
      }
    """
    if top_n <= 0 or top_n > 200:
        raise ToolError("top_n must be in 1..200")
    p = safe_input_path(path)
    host_lc = host_filter.lower()

    pcap = pcap_info(str(p))

    # --- DNS ---
    dns_args = _lua_args() + [
        "-r", str(p), "-Y", "dns.flags.response == 1",
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a",
        "-e", "dns.qry.name", "-e", "dns.a", "-e", "dns.aaaa", "-e", "dns.cname",
    ]
    dns_by_name: dict[str, dict[str, set[str]]] = {}
    for line in run("tshark", dns_args).stdout.splitlines():
        if not line:
            continue
        cols = (line.split("\t") + [""] * 4)[:4]
        name, a, aaaa, cname = cols
        if not name:
            continue
        if host_lc and host_lc not in name.lower():
            continue
        e = dns_by_name.setdefault(name, {"ips": set(), "cnames": set()})
        for v in (a + "," + aaaa).split(","):
            v = v.strip()
            if v:
                e["ips"].add(v)
        for c in cname.split(","):
            c = c.strip()
            if c:
                e["cnames"].add(c)
    dns_rows = [
        {"name": n, "ips": sorted(d["ips"]), "cnames": sorted(d["cnames"])}
        for n, d in dns_by_name.items()
    ]
    dns_rows.sort(key=lambda x: x["name"])

    # --- TLS ---
    hellos = tls_hellos(str(p))
    tls_groups: dict[tuple[str, str, int], dict[str, Any]] = {}
    for h in hellos:
        if host_lc and host_lc not in (h.get("sni") or "").lower():
            continue
        key = (h.get("sni", ""), h["dst"], h["dport"])
        g = tls_groups.setdefault(key, {
            "sni": h.get("sni", ""), "dst": h["dst"], "dport": h["dport"],
            "hellos": 0, "first_t": h["t"],
        })
        g["hellos"] += 1
        if h["t"] < g["first_t"]:
            g["first_t"] = h["t"]
    tls_rows = sorted(tls_groups.values(), key=lambda x: x["first_t"])

    # --- conversations (TCP + UDP) ---
    # Determine an IP allowlist when host_filter is in play: any IP that
    # appeared in a DNS or TLS row we kept. Falls back to "all" if nothing
    # was kept.
    ip_allow: set[str] | None = None
    if host_lc:
        ip_allow = set()
        for r in dns_rows:
            ip_allow.update(r["ips"])
        for r in tls_rows:
            ip_allow.add(r["dst"])

    def _conv_rows(layer: str) -> list[dict[str, Any]]:
        # Parse tshark's `-z conv,<layer>` ASCII table. Format (post-header):
        #   <a> <-> <b>   <frames_b_to_a> <bytes_b_to_a>
        #                 <frames_a_to_b> <bytes_a_to_b>
        #                 <total_frames> <total_bytes>
        #                 <rel_start>     <duration>
        try:
            res = run(
                "tshark",
                _lua_args() + ["-r", str(p), "-q", "-z", f"conv,{layer}"],
            )
        except ToolError:
            return []
        rows: list[dict[str, Any]] = []

        def _num(s: str) -> float:
            s = s.replace(",", "").replace(" ", "")
            try:
                return float(s)
            except ValueError:
                return 0.0

        def _bytes(value: str, unit: str) -> int:
            n = _num(value)
            mult = {"bytes": 1, "kB": 1000, "MB": 1_000_000, "GB": 1_000_000_000}
            return int(n * mult.get(unit, 1))

        # Table layout (post-header):
        #   <a> <-> <b>  <frames_b_to_a> <bytes_b_to_a><unit>
        #               <frames_a_to_b> <bytes_a_to_b><unit>
        #               <total_frames>  <total_bytes><unit>
        #               <rel_start>     <duration>
        in_table = False
        for line in res.stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if not in_table:
                if "<->" in stripped and "Frames" not in stripped:
                    in_table = True
                else:
                    continue
            if "<->" not in stripped:
                continue
            parts = stripped.split()
            try:
                idx = parts.index("<->")
            except ValueError:
                continue
            if idx + 1 >= len(parts):
                continue
            a = parts[idx - 1]
            b = parts[idx + 1]
            nums = parts[idx + 2 :]
            # Expect (frames, bytes, unit) x 3, then (rel_start, duration).
            # Some tshark versions emit "bytes" as a single token without a
            # unit suffix. Walk pairs.
            def _take(tokens: list[str]) -> tuple[int, int, list[str]]:
                if not tokens:
                    return 0, 0, tokens
                frames = int(_num(tokens[0]))
                if len(tokens) >= 3 and tokens[2] in {"bytes", "kB", "MB", "GB"}:
                    by = _bytes(tokens[1], tokens[2])
                    return frames, by, tokens[3:]
                by = int(_num(tokens[1])) if len(tokens) > 1 else 0
                return frames, by, tokens[2:]

            f_ba, by_ba, rest = _take(nums)
            f_ab, by_ab, rest = _take(rest)
            _ft, _bt, rest = _take(rest)
            duration = 0.0
            if len(rest) >= 2:
                duration = _num(rest[1])
            rows.append({
                "a": a, "b": b,
                "frames_a_to_b": f_ab, "bytes_a_to_b": by_ab,
                "frames_b_to_a": f_ba, "bytes_b_to_a": by_ba,
                "total_bytes": by_ab + by_ba,
                "duration": duration,
            })
        # Filter by ip_allow if set.
        if ip_allow is not None:
            def _has_allowed(ep: str) -> bool:
                ip = ep.rsplit(":", 1)[0]
                return ip in ip_allow
            rows = [r for r in rows if _has_allowed(r["a"]) or _has_allowed(r["b"])]
        rows.sort(key=lambda r: r["total_bytes"], reverse=True)
        for r in rows:
            r.pop("total_bytes", None)
        return rows[:top_n]

    conv = {"tcp": _conv_rows("tcp"), "udp": _conv_rows("udp")}

    # --- HTTP (cleartext only) ---
    http_args = _lua_args() + [
        "-r", str(p), "-Y", "http.request or http.response",
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
        "-e", "frame.time_relative", "-e", "http.host", "-e", "http.request.method",
        "-e", "http.request.uri", "-e", "http.response.code",
        "-e", "http.content_length",
    ]
    http_rows: list[dict[str, Any]] = []
    try:
        for line in run("tshark", http_args).stdout.splitlines():
            if not line:
                continue
            cols = (line.split("\t") + [""] * 6)[:6]
            t, host, method, uri, status, clen = cols
            if host_lc and host and host_lc not in host.lower():
                continue
            if not (host or method or status):
                continue
            try:
                resp_bytes = int(clen) if clen else 0
            except ValueError:
                resp_bytes = 0
            http_rows.append({
                "t": float(t) if t else 0.0,
                "host": host, "method": method, "uri": uri,
                "status": int(status) if status else None,
                "resp_bytes": resp_bytes,
            })
    except ToolError:
        pass
    http_rows = http_rows[:top_n]

    return {
        "pcap": pcap,
        "dns": dns_rows[:top_n],
        "tls": tls_rows[:top_n],
        "conversations": conv,
        "http_requests": http_rows,
    }


# --- socket-to-process attribution ----------------------------------------
#
# Pure /proc walker (Linux). Maps remote endpoints seen in a pcap to the
# process that owns the local socket, so an LLM can answer "which app made
# this connection?" without running ss/lsof. Best-effort: a socket that
# has already closed by the time you call this won't appear.

_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV",
}


def _parse_proc_net_addr(hex_addr: str, hex_port: str) -> tuple[str, int]:
    """Decode the hex-encoded address/port format used in /proc/net/{tcp,udp}{,6}.

    IPv4 (8 hex chars): bytes are *byte-reversed* (little-endian per word).
    IPv6 (32 hex chars): each 32-bit word is byte-reversed, but the 4 words
    are in network order.
    """
    port = int(hex_port, 16)
    if len(hex_addr) == 8:
        b = bytes.fromhex(hex_addr)
        ip = ".".join(str(x) for x in reversed(b))
    elif len(hex_addr) == 32:
        # 4 little-endian 32-bit words, joined in order.
        words = [hex_addr[i : i + 8] for i in range(0, 32, 8)]
        be = b"".join(bytes.fromhex(w)[::-1] for w in words)
        # Format as colon-separated 16-bit groups, compress with ipaddress.
        import ipaddress
        ip = str(ipaddress.IPv6Address(be))
    else:
        ip = hex_addr
    return ip, port


def _read_proc_net(proto: str) -> list[dict[str, Any]]:
    """Return all sockets from /proc/net/{tcp,udp}{,6}, one dict per row."""
    paths = []
    if proto in ("tcp", "all"):
        paths += [("tcp", "/proc/net/tcp"), ("tcp", "/proc/net/tcp6")]
    if proto in ("udp", "all"):
        paths += [("udp", "/proc/net/udp"), ("udp", "/proc/net/udp6")]
    rows: list[dict[str, Any]] = []
    for p, path in paths:
        try:
            with open(path) as f:
                next(f, None)  # header
                for line in f:
                    cols = line.split()
                    if len(cols) < 10:
                        continue
                    try:
                        l_ha, l_hp = cols[1].split(":")
                        r_ha, r_hp = cols[2].split(":")
                        l_ip, l_port = _parse_proc_net_addr(l_ha, l_hp)
                        r_ip, r_port = _parse_proc_net_addr(r_ha, r_hp)
                        inode = int(cols[9])
                    except (ValueError, IndexError):
                        continue
                    rows.append({
                        "proto": p,
                        "local_ip": l_ip,
                        "local_port": l_port,
                        "remote_ip": r_ip,
                        "remote_port": r_port,
                        "state": _TCP_STATES.get(cols[3].upper(), cols[3]) if p == "tcp" else "",
                        "inode": inode,
                    })
        except FileNotFoundError:
            continue
    return rows


def _inode_to_pid() -> dict[int, dict[str, Any]]:
    """Walk /proc/<pid>/fd/* to build {inode: {pid, comm}}.

    Skips processes we can't read (different uid, gone-away PIDs). The
    returned dict is best-effort — sockets owned by other users won't map.
    """
    out: dict[int, dict[str, Any]] = {}
    try:
        pids = [name for name in os.listdir("/proc") if name.isdigit()]
    except OSError:
        return out
    for pid_s in pids:
        fd_dir = f"/proc/{pid_s}/fd"
        try:
            fds = os.listdir(fd_dir)
        except (FileNotFoundError, PermissionError, NotADirectoryError):
            continue
        comm = ""
        try:
            with open(f"/proc/{pid_s}/comm") as f:
                comm = f.read().strip()
        except (FileNotFoundError, PermissionError):
            pass
        for fd in fds:
            try:
                link = os.readlink(f"{fd_dir}/{fd}")
            except (FileNotFoundError, PermissionError):
                continue
            if link.startswith("socket:["):
                try:
                    inode = int(link[8:-1])
                except ValueError:
                    continue
                # First writer wins (lowest pid usually); don't overwrite.
                out.setdefault(inode, {"pid": int(pid_s), "comm": comm})
    return out


def _pcap_endpoints(path: Path, proto: str) -> dict[tuple[str, str, int], dict[str, int]]:
    """Extract (proto, remote_ip, remote_port) → {packets, bytes} from a pcap.

    Direction-agnostic: we don't know which side is local from the pcap alone,
    so we return both endpoints of every conversation. Callers cross-reference
    with /proc/net to figure out which one is local.
    """
    out: dict[tuple[str, str, int], dict[str, int]] = {}
    for p in (["tcp"] if proto == "tcp" else ["udp"] if proto == "udp" else ["tcp", "udp"]):
        field_list = [
            "ip.src", "ipv6.src", f"{p}.srcport",
            "ip.dst", "ipv6.dst", f"{p}.dstport",
            "frame.len",
        ]
        args = ["-r", str(path), "-Y", p,
                "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
        for f in field_list:
            args += ["-e", f]
        try:
            res = run("tshark", _lua_args() + args)
        except ToolError:
            continue
        for line in res.stdout.splitlines():
            if not line:
                continue
            cols = (line.split("\t") + [""] * len(field_list))[:len(field_list)]
            ip4s, ip6s, sport, ip4d, ip6d, dport, flen = cols
            src_ip, dst_ip = ip4s or ip6s, ip4d or ip6d
            if not src_ip or not dst_ip or not sport or not dport:
                continue
            try:
                sp, dp, fl = int(sport), int(dport), int(flen) if flen else 0
            except ValueError:
                continue
            for ip, port in ((src_ip, sp), (dst_ip, dp)):
                key = (p, ip, port)
                e = out.setdefault(key, {"packets": 0, "bytes": 0})
                e["packets"] += 1
                e["bytes"] += fl
    return out


@mcp.tool()
def socket_owners(path: str = "", proto: str = "all") -> dict[str, Any]:
    """Attribute pcap conversations to local processes via /proc (Linux only).

    Best-effort socket → PID mapping. Reads `/proc/net/{tcp,udp}{,6}` for the
    current open-socket table and walks `/proc/<pid>/fd/*` to find the owner.
    Only sockets *still open right now* can be attributed; a connection that
    closed since the pcap was captured will be missing. Sockets owned by
    other UIDs are visible in /proc/net but may not map to a PID without
    root (we silently skip those).

    Modes:
    - `path` empty: return a snapshot of *all* current sockets with their
      owning process. Handy as a standalone "what's connected and who owns
      it" view.
    - `path` set: extract every TCP+UDP endpoint pair from the pcap and
      attribute the ones whose local side is still open. Returned in
      `matched`. Endpoints that didn't map appear in `unmatched_remotes`.

    `proto`: `"tcp"`, `"udp"`, or `"all"`.

    Returns (path mode):
        {
          "matched": [{proto, local, remote, pid, comm, state,
                       packets_in_pcap, bytes_in_pcap}, ...],
          "unmatched_remotes": [{proto, endpoint, packets, bytes}, ...],
          "open_sockets_total": int,
        }
    Returns (no path):
        {
          "sockets": [{proto, local, remote, state, pid, comm}, ...],
          "open_sockets_total": int,
        }
    """
    if proto not in ("tcp", "udp", "all"):
        raise ToolError("proto must be one of tcp, udp, all")
    if sys.platform != "linux":
        raise ToolError("socket_owners is Linux-only (reads /proc)")

    sockets = _read_proc_net(proto)
    owners = _inode_to_pid()

    enriched: list[dict[str, Any]] = []
    for s in sockets:
        own = owners.get(s["inode"]) or {}
        enriched.append({
            "proto": s["proto"],
            "local": f"{s['local_ip']}:{s['local_port']}",
            "remote": f"{s['remote_ip']}:{s['remote_port']}" if s["remote_port"] else "",
            "state": s["state"],
            "pid": own.get("pid"),
            "comm": own.get("comm", ""),
        })

    if not path:
        return {"sockets": enriched, "open_sockets_total": len(enriched)}

    p = safe_input_path(path)
    endpoints = _pcap_endpoints(p, proto)

    # Index sockets by (proto, ip, port) for fast lookup. We want to match
    # the *local* side of the socket against pcap endpoints — that gives us
    # "this app talked to <remote>". A pcap endpoint may match a local OR
    # remote socket field; we prefer local-side matches.
    by_local: dict[tuple[str, str, int], dict[str, Any]] = {}
    for s in sockets:
        own = owners.get(s["inode"]) or {}
        rec = {
            "proto": s["proto"],
            "local": f"{s['local_ip']}:{s['local_port']}",
            "remote": f"{s['remote_ip']}:{s['remote_port']}" if s["remote_port"] else "",
            "state": s["state"],
            "pid": own.get("pid"),
            "comm": own.get("comm", ""),
        }
        by_local[(s["proto"], s["local_ip"], s["local_port"])] = rec

    matched: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    seen_socket_keys: set[tuple[str, str, int]] = set()

    # For each (proto, ip, port) endpoint in the pcap, see if any open socket
    # has *that* as its local address — meaning this host's socket is the
    # one that captured side belongs to.
    for (pr, ip, port), counts in endpoints.items():
        sock = by_local.get((pr, ip, port))
        if sock is None:
            # Try the wildcard local: many listening sockets bind 0.0.0.0/::.
            sock = by_local.get((pr, "0.0.0.0", port)) or by_local.get((pr, "::", port))
        if sock is not None:
            key = (sock["proto"], sock["local"], port)
            if key in seen_socket_keys:
                continue
            seen_socket_keys.add(key)
            matched.append({
                **sock,
                "packets_in_pcap": counts["packets"],
                "bytes_in_pcap": counts["bytes"],
            })
        else:
            unmatched.append({
                "proto": pr,
                "endpoint": f"{ip}:{port}",
                "packets": counts["packets"],
                "bytes": counts["bytes"],
            })

    # Sort matched by traffic descending, unmatched by traffic descending.
    matched.sort(key=lambda x: x["bytes_in_pcap"], reverse=True)
    unmatched.sort(key=lambda x: x["bytes"], reverse=True)

    return {
        "matched": matched,
        "unmatched_remotes": unmatched[:50],  # bound output
        "unmatched_count": len(unmatched),
        "open_sockets_total": len(sockets),
    }


def _reexec_with_capture_group() -> None:
    """Self-heal for the common 'dumpcap: Permission denied' case.

    dumpcap typically ships mode 0750 root:wireshark with cap_net_admin,cap_net_raw=eip.
    If the user was added to the `wireshark` group after their login session started,
    /etc/group lists them but their active process groups don't — so dumpcap exec
    fails until they log out and back in. We detect that mismatch and re-exec under
    `sg <group> -c …`, which grants the group to the new process.
    """
    if os.environ.get("WIRESHARK_MCP_GROUP_REEXECED") == "1":
        return
    # Don't use shutil.which — it filters by os.access(X_OK), which returns
    # False precisely in the case we're trying to detect.
    dumpcap = None
    st = None
    for candidate in ("/usr/local/bin/dumpcap", "/usr/bin/dumpcap", "/usr/sbin/dumpcap"):
        try:
            st = os.stat(candidate)
        except OSError:
            continue
        dumpcap = candidate
        break
    if not dumpcap:
        return
    # Only act when the binary is group-executable but not world-executable —
    # the classic 0750 root:wireshark layout.
    if (st.st_mode & stat.S_IXOTH) or not (st.st_mode & stat.S_IXGRP):
        return
    if os.access(dumpcap, os.X_OK):
        return
    try:
        grp_entry = grp.getgrgid(st.st_gid)
    except KeyError:
        return
    gid = grp_entry.gr_gid
    if gid in os.getgroups() or gid == os.getegid():
        return
    user = os.environ.get("USER") or ""
    if user and user not in grp_entry.gr_mem:
        # User isn't actually a member — re-exec would prompt for a password.
        return
    sg = shutil.which("sg")
    if not sg:
        return
    inner = shlex.join([sys.executable, "-m", "wireshark_mcp", *sys.argv[1:]])
    env = {**os.environ, "WIRESHARK_MCP_GROUP_REEXECED": "1"}
    os.execvpe(sg, [sg, grp_entry.gr_name, "-c", inner], env)


@asynccontextmanager
async def _raw_stdio_server():
    """Stdio transport that avoids host-specific hangs in anyio.wrap_file."""
    read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
    write_stream, write_stream_reader = anyio.create_memory_object_stream(0)
    debug_stdio = os.environ.get("WIRESHARK_MCP_DEBUG_STDIO") == "1"

    def _debug(message: str) -> None:
        if debug_stdio:
            print(f"wireshark-mcp stdio: {message}", file=sys.stderr, flush=True)

    def _write(data: bytes) -> None:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    async def _wait_readable(fd: int) -> None:
        loop = asyncio.get_running_loop()
        fut = loop.create_future()

        def ready() -> None:
            if not fut.done():
                fut.set_result(None)

        loop.add_reader(fd, ready)
        try:
            await fut
        finally:
            loop.remove_reader(fd)

    async def stdin_reader() -> None:
        try:
            async with read_stream_writer:
                fd = sys.stdin.buffer.fileno()
                os.set_blocking(fd, False)
                buffer = b""
                while True:
                    _debug("waiting for stdin bytes")
                    await _wait_readable(fd)
                    try:
                        chunk = os.read(fd, 65536)
                    except BlockingIOError:
                        continue
                    _debug(f"read {len(chunk)} bytes")
                    if not chunk:
                        break
                    buffer += chunk
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if line:
                            try:
                                message = mcp_types.JSONRPCMessage.model_validate_json(
                                    line.decode("utf-8", errors="replace")
                                )
                            except Exception as exc:
                                await read_stream_writer.send(exc)
                                continue
                            await read_stream_writer.send(SessionMessage(message))
                if buffer:
                    try:
                        message = mcp_types.JSONRPCMessage.model_validate_json(
                            buffer.decode("utf-8", errors="replace")
                        )
                    except Exception as exc:
                        await read_stream_writer.send(exc)
                    else:
                        await read_stream_writer.send(SessionMessage(message))
        except anyio.ClosedResourceError:  # pragma: no cover
            await anyio.lowlevel.checkpoint()

    async def stdout_writer() -> None:
        try:
            async with write_stream_reader:
                async for session_message in write_stream_reader:
                    payload = session_message.message.model_dump_json(
                        by_alias=True, exclude_none=True
                    )
                    _write((payload + "\n").encode("utf-8"))
        except anyio.ClosedResourceError:  # pragma: no cover
            await anyio.lowlevel.checkpoint()

    async with anyio.create_task_group() as tg:
        tg.start_soon(stdin_reader)
        tg.start_soon(stdout_writer)
        try:
            yield read_stream, write_stream
        finally:
            tg.cancel_scope.cancel()


async def _run_stdio() -> None:
    async with _raw_stdio_server() as (read_stream, write_stream):
        await mcp._mcp_server.run(
            read_stream,
            write_stream,
            mcp._mcp_server.create_initialization_options(),
        )


def main() -> None:
    _reexec_with_capture_group()
    logging.getLogger("mcp").setLevel(logging.WARNING)
    anyio.run(_run_stdio)


if __name__ == "__main__":
    main()
