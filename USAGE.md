# Wireshark MCP — Usage

MCP server that lets an LLM drive Wireshark CLI tools (`tshark`, `dumpcap`,
`editcap`, `capinfos`, `mergecap`) without user interaction.

## Project layout

```
WiresharkMCP/
├── pyproject.toml
├── install.sh                      # one-shot install / re-sync (run after edits)
├── .gitignore
├── CLAUDE.md                       # goals / instructions
├── USAGE.md                        # this file
├── .venv/                          # installed editable + mcp SDK
└── wireshark_mcp/
    ├── __init__.py
    ├── __main__.py                 # `python -m wireshark_mcp`
    ├── runner.py                   # subprocess + sandbox + size/timeout caps
    └── server.py                   # FastMCP + tools + resources
```

## Tools

| Tool | Wraps | Purpose |
|---|---|---|
| `help` | (in-memory) | LLM-friendly overview — call first if unfamiliar with the server |
| `list_interfaces` | `tshark -D` | discover capture sources |
| `capture` | `dumpcap -i … -c … -a duration:…` | bounded live capture into the sandbox |
| `pcap_info` | `capinfos` | size, duration, packet count, hashes |
| `read_packets` | `tshark -r … [-Y filter] -T json\|fields` | filtered packet read, JSON or tabular |
| `protocol_hierarchy` | `tshark -q -z io,phs` | what protocols are in the file |
| `io_stat` | `tshark -q -z io,stat,N[,filter,...]` | time-bucketed packet/byte counts; optional per-filter columns |
| `conversations` | `tshark -q -z conv,{tcp,udp,ip,ipv6,eth} [-2 -R filter]` | endpoint-pair stats; optional `display_filter` to drop noisy endpoints |
| `tls_hellos` | `tshark -Y "tls.handshake.type==1" -e tls.handshake.extensions_server_name` | every TLS ClientHello with SNI — `{frame, t, dst, dport, sni}` |
| `follow_stream` | `tshark -q -z follow,{tcp,udp,tls,http},…` | reassemble a single stream |
| `extract_range` | `editcap -r in out A-B` | carve a packet range into a new pcap |
| `decode_as` | `tshark -d <layer>==<port>,<proto>` | force-decode non-standard ports (e.g. SSH on 2222) |
| `tcp_stats` | `tshark -Y tcp.analysis.flags` + `-e tcp.analysis.ack_rtt` | retransmission / dup-ack / zero-window counts + RTT min/avg/max/p50/p95 |
| `udp_payloads` | `tshark -T fields -e udp.payload …` | one row per UDP packet: `{frame, t, src, dst, len, hex}` (optionally byte-sliced) |
| `udp_streams` | `tshark -T fields -e udp.stream …` | list every UDP stream with `index` (use with `follow_stream`), endpoints, packet/byte counts, duration |
| `udp_stats` | `tshark -T fields -e udp.stream -e udp.length …` | per-flow packets/sec, bytes/sec, payload-size + inter-arrival-jitter summaries |
| `decode_payload` | (in-process `struct.unpack`) | parse raw bytes by a Python-struct spec — no Lua dissector needed |
| `write_dissector` / `load_dissector` / `unload_dissector` / `list_dissectors` | writes to `~/.wireshark-mcp/dissectors/`, passes `-X lua_script:…` to every tshark call | manage custom Lua dissectors for proprietary protocols |
| `live_tail_start` / `live_tail_read` / `live_tail_wait_quiet` / `live_tail_stop` | `dumpcap` (background) + `tshark -Y "frame.number > N"` | long-running capture with incremental, since-last-read fetches; `live_tail_wait_quiet` blocks until the capture file (or, with `display_filter`, only matching packets) have been idle for N seconds |
| `summary` | (composes `capinfos` + DNS + `tls_hellos` + `conv,{tcp,udp}` + HTTP) | one-shot "what happened in this pcap?" rollup; optional `host_filter` substring narrows to a single endpoint |
| `socket_owners` | `/proc/net/{tcp,udp}{,6}` + `/proc/<pid>/fd/*` walk | Linux-only: attribute pcap conversations to the local PID/comm that owns the socket. Best-effort — only works while the socket is still open. |
| `list_captures` | (sandbox dir) | enumerate pcaps in `~/.wireshark-mcp/captures/`, return URIs |
| `mitm_start` / `mitm_flows` / `mitm_flow_body` / `mitm_ws_messages` / `mitm_stop` | `mitmweb --mode local:<proc>` (background) + auth'd HTTP API + on-disk flow stream | spawn TLS-intercepting proxy scoped to one process via eBPF; list decrypted flows; dump request/response bodies; read decrypted WebSocket message frames. See "TLS interception" below. |

### Tool details

**`decode_as`** — accepts a list of rules like `["tcp.port==2222,ssh", "udp.port==5060,sip"]`. Each rule must match `<layer.field>==<port-or-range>,<protocol>` or it's rejected. Returns the same shape as `read_packets` (JSON unless `fields` is provided).

**`io_stat`** — bucket the capture by time and count packets/bytes per bucket. Pass `interval_seconds=N` (use `0` for "whole capture as one bucket") and optionally a list of up to 8 Wireshark display filters in `filters=[...]`. Each filter produces its own Frames+Bytes column, so you can quickly see *when* a particular protocol/host/handshake fires. Sample:

```python
io_stat("capture.pcap", interval_seconds=5, filters=[
    'tls.handshake.extensions_server_name contains "example.com"',
    'http.request',
])
# → {"interval_seconds": 5, "columns": [...], "buckets": [
#       {"start": 0, "end": 5,  "counts": [0, 0],  "bytes": [0, 0]},
#       {"start": 45, "end": 50, "counts": [1, 782], "bytes": [398, 245939]},
#       ...]}
```

Without `filters`, you get one column with all-traffic Frames+Bytes per bucket — the cheapest way to find traffic peaks in a busy capture.

**`tls_hellos`** — list every TLS ClientHello with its destination and Server Name Indication (SNI). The fast way to identify *who* an opaque HTTPS-using process is talking to, without decrypting anything. Returns one row per ClientHello: `{frame, t, dst, dport, sni}`. Optional `display_filter` is AND-ed with `tls.handshake.type == 1`.

**`tcp_stats`** — runs two tshark passes:
1. anomaly counts from `tcp.analysis.{retransmission, fast_retransmission, spurious_retransmission, duplicate_ack, zero_window, window_full, out_of_order, lost_segment, keep_alive}`
2. RTT distribution from every `tcp.analysis.ack_rtt`

Optional `display_filter` (e.g. `ip.addr==10.0.0.5`) scopes both passes. Sample output:

```json
{
  "flagged_packets": 4,
  "flag_counts": {"retransmission": 1, "duplicate_ack": 2, "keep_alive": 1, ...},
  "ack_rtt_seconds": {"samples": 13, "min": 0.006, "avg": 0.049, "p95": 0.122, ...}
}
```

### Debugging custom binary protocols (Unity games, IoT, proprietary UDP)

There are two paths, pick whichever matches your maturity:

**Path A — quick exploration without writing Lua.** Use `udp_payloads` to dump raw hex per packet (slice with `byte_offset` / `byte_length` for compactness), then feed individual payloads to `decode_payload` with a Python-struct-style spec. Spec example: `"< B opcode; H seq; f x; f y; f z"`. Endianness prefix: `<>!=@` or the words `BE` / `LE` (default `<`). Each field is `<format> <name>` separated by `;`. `<format>` is any Python `struct` token (`B`, `H`, `I`, `Q`, `f`, `d`, `10s`, …). You can also pass `(path, frame_number)` instead of `hex_payload` to pull a frame's UDP payload straight from a pcap.

**Path B — once the protocol stabilizes, write a Lua dissector.** Call `write_dissector(name="mygame.lua", lua_source="…")` to save it under `~/.wireshark-mcp/dissectors/`, then `load_dissector("mygame.lua")` to register it. Every subsequent tshark call (`read_packets`, `decode_as`, `follow_stream`, `udp_payloads`, `udp_streams`, `udp_stats`, `tcp_stats`, `protocol_hierarchy`, `conversations`, `live_tail_read`) loads it via `-X lua_script:…`, so you can filter on `mygame.opcode == 2` and tabulate `mygame.x`, `mygame.y`, … like any built-in protocol. `unload_dissector(name)` stops using it (file stays on disk); `list_dissectors()` shows files + loaded set.

Pcap directory inside the sandbox: `~/.wireshark-mcp/dissectors/` (override with `WIRESHARK_MCP_DISSECTOR_DIR`).

### Live tailing

`live_tail_start(interface, capture_filter, max_duration_seconds=600, max_packets=100000)` spawns `dumpcap` in the background and returns `{handle, path, pid, interface}`. Then `live_tail_read(handle, display_filter, max_packets, fields)` returns `{packets, last_frame, alive}` — only packets with `frame.number > last_frame` from the previous read, same `fields=` semantics as `read_packets`. `live_tail_stop(handle)` flushes and ends. Tails self-terminate at the duration/packet caps (1h / 100k); any still alive at server exit are cleaned up via `atexit`. The capture file persists in the sandbox so you can re-analyze with the static tools afterwards.

`live_tail_wait_quiet(handle, quiet_seconds=5, max_wait_seconds=120, display_filter="")` blocks until the activity signal has been idle for `quiet_seconds`, then returns `{reason, waited_seconds, last_size_bytes, alive}`. `reason` is `"quiet"` (idle threshold met), `"timeout"` (max_wait elapsed), or `"exited"` (dumpcap stopped). Use this to reliably catch trailing traffic — e.g. a game's round-end POST that fires a few seconds after the round visually ends — instead of guessing how long to sleep before calling `live_tail_stop`.

Two modes:
- Default: signal is the capture file's size on disk. Cheap. Useless on a busy interface, because unrelated flows keep the file growing.
- `display_filter` set: signal is the count of matching packets (each poll runs tshark with `-Y <filter>`). Use to wait for a specific conversation to fall idle while ignoring noise (e.g. `display_filter='tls.handshake.extensions_server_name contains "example.com"'`). Bump `poll_interval_seconds` to ≥ 2 if the capture file is large. The return dict gains a `matched_packets` field.

### Summary (one-shot rollup)

`summary(path, host_filter="", top_n=20)` collapses 3–4 separate tool calls into one. Returns `{pcap, dns, tls, conversations: {tcp, udp}, http_requests}`:

- `pcap` — `capinfos` summary fields
- `dns` — one entry per unique queried name, with all A/AAAA answers and CNAMEs
- `tls` — one entry per `(SNI, dst, dport)`, with ClientHello count and first-seen timestamp
- `conversations` — top-N TCP and UDP endpoint pairs sorted by total bytes (parsed from `tshark -z conv,…`)
- `http_requests` — cleartext HTTP requests with host, method, URI, status, response bytes

`host_filter` is a case-insensitive substring: it drops DNS rows whose name doesn't contain it, TLS rows whose SNI doesn't contain it, HTTP rows whose host doesn't, and conversation rows whose endpoints' IPs never appeared in any matching DNS or TLS row. Effectively gives you "everything to/from one host."

### Socket → process attribution

`socket_owners(path="", proto="all")` cross-references pcap conversations with currently-open sockets on the local host. Linux-only (reads `/proc/net/{tcp,udp}{,6}` and walks `/proc/<pid>/fd/*`). Best-effort: a socket that's already closed by the time you call this won't be in `/proc`, so it can't be attributed. Sockets owned by other UIDs may not map to a PID without root — they're silently skipped.

Two modes:
- `path` empty: snapshot of every current socket with `{proto, local, remote, state, pid, comm}`. Useful as a standalone "what's connected and who owns it" view.
- `path` set: returns `matched` (sockets whose local side matches an endpoint in the pcap, each with `packets_in_pcap` / `bytes_in_pcap`) and `unmatched_remotes` (endpoints in the pcap with no matching open socket — usually because the connection has already closed).

### TLS interception (mitmproxy integration)

`mitm_start(process_name, web_port=8081)` spawns `mitmweb` in
`--mode local:<process_name>` mode and returns
`{handle, web_url, web_port, process_name, pid, ca_cert_path}`. The
process-local mode uses an eBPF redirector (spawned via `sudo`) to grab
only the named binary's outbound connections; everything else on the
host — including this MCP server — is untouched. Open `web_url` in a
browser to see decrypted flows in real time; the URL embeds a session
token, so no separate auth step is needed.

Prereqs:

- `mitmweb` on `PATH` from mitmproxy ≥ 10. The Ubuntu/Debian package is
  usually too old; install with `pipx install mitmproxy`.
- Passwordless `sudo` (mitmweb invokes the redirector via `sudo`).
- Linux kernel ≥ 5.7 (for the eBPF features the redirector needs).

`mitm_flows(handle, host_contains="", flow_type="", limit=100)` returns
one summary row per flow, newest first. For HTTP flows: `{flow_id,
type, ts, method, scheme, host, path, status, req_bytes, res_bytes,
ws_msg_count, ws_bytes, ws_closed}`. For tcp/udp/dns: `{flow_id, type,
ts, client, server}`. `flow_type` restricts to one of `http`, `tcp`,
`udp`, `dns`. `host_contains` is a case-insensitive substring filter
on HTTP host.

`mitm_flow_body(handle, flow_id, direction, max_bytes=65536)` dumps the
raw request or response body of one HTTP flow. Returns the bytes as
utf-8 text when they decode cleanly, otherwise as lowercase hex with
`encoding: "hex"`. For WebSocket flows this returns the HTTP/1.1 upgrade
request/response, not the frames — use `mitm_ws_messages` for those.

`mitm_ws_messages(handle, flow_id, limit=100, max_bytes_per_message=8192,
offset=0)` returns decrypted WebSocket message frames for a single flow.
Each message has `from_client`, `direction`, `opcode` (`text`/`binary`),
`ts`, `total_bytes`, `truncated`, `encoding` (`utf-8`/`hex`), `content`,
`dropped`, `injected`. Page through with `offset`+`limit`; `total_messages`
is the full count. Frames are read from the per-session flow stream file
that `mitm_start` opens with `--save-stream-file`; mitmproxy only flushes
a flow once it's closed, so a long-lived WebSocket may not appear here
until the connection ends (e.g. after quitting the app).

`mitm_stop(handle)` SIGINTs the mitm process, removes the handle, and
returns the exit code plus the tail of mitm's stdout for debugging.
Any still-running mitm session is terminated automatically at MCP
server exit.

**CA trust gotcha.** TLS interception requires the target app to trust
mitmproxy's CA cert (`~/.mitmproxy/mitmproxy-ca-cert.pem`). Apps that
read the OS trust store work after one-time
`sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt && sudo update-ca-certificates`.
Some runtimes ignore the OS store entirely (engines that ship a
compiled-in Mozilla bundle, sandboxed runtimes). When that's the case
you'll see `Client TLS handshake failed ... tlsv1 alert unknown ca` in
mitm's log; the fix is engine-specific.

See [docs/tls-override.md](docs/tls-override.md) for a
table of hooks per runtime (Godot 3/4, Unity Mono / IL2CPP, Java JRE,
Node.js / Electron, Python `requests` / `httpx`, Go, Rust `rustls`, …)
with recipes and diagnostic snippets. Extend that file whenever you
work out a new engine override.

**Sudo gotcha.** mitmweb spawns `mitmproxy-linux-redirector` via `sudo`.
If your sudoers prompts for a password, `mitm_start` now detects this
and fails fast with a hint — run `sudo true` once in any terminal (the
ticket caches for ~15 min) or add a NOPASSWD rule for the redirector
binary.

### UDP traffic analysis

`udp_streams(path)` gives every UDP 5-tuple grouped by Wireshark's `udp.stream` index, with packet/byte counts and time range — pair with `follow_stream(proto="udp", stream_index=N)` to reassemble payloads. `udp_stats(path)` groups per (stream, src→dst) and adds packets/sec, bytes/sec, payload-size summary, and inter-arrival-jitter summary (min/avg/max/p50/p95). Useful for finding tick stutters and attributing them to client vs. server.

## Resources

The MCP server exposes two resources:

| URI | MIME | Returns |
|---|---|---|
| `wireshark://usage` | `text/markdown` | Same content as the `help` tool — server overview, workflows, filter-syntax pitfalls |
| `capture://{name}` | `text/plain` | `capinfos` summary of `~/.wireshark-mcp/captures/{name}` |

Pair `capture://{name}` with `list_captures` to browse: the LLM calls `list_captures()`, sees a list with `uri` fields like `capture://capture-1715620000.pcapng`, then asks the host to **read the resource** for any of them to get a summary without re-running analysis tools. Reads outside the sandbox are rejected.

## Discovery for LLMs

If an LLM connects without prior knowledge of the server, two equally good entry points:

1. **Tool**: call `help()` — returns markdown including a "where to start" decision table, filter-syntax warnings, output limits, and a live list of every registered tool.
2. **Resource**: read `wireshark://usage` — identical content, surfaces in `resources/list` for hosts that prefer resource-based discovery.

The `help` tool's own docstring tells the LLM to call it first, so it's visible in `tools/list` even before invocation.

## Install & update — one command

```bash
./install.sh
```

That single script:

1. Takes a per-checkout install lock so two installs cannot race
2. Ignores any unrelated active virtualenv and uses this checkout's `.venv/`
3. Stops any existing/stuck Wireshark MCP process from this checkout
4. Creates / reuses the `.venv/`
5. Installs the package in editable mode (`pip install -e .`)
6. Imports `wireshark_mcp.server` to fail fast if anything is broken
7. Re-registers Claude Code and Codex with the current venv path

Run it again any time you pull changes, edit dependencies, or change the venv
location. Because the package is editable, source-only edits don't require a
re-install — but re-running is always safe.

After the script reports success, **toggle `wireshark` in the Claude Code
VS Code extension's MCP panel** like any other MCP server.

Optional flag — install at project scope instead of user-global:

```bash
WIRESHARK_MCP_SCOPE=local ./install.sh
```

Sample prompts to test the connection:

- *"list my network interfaces"*
- *"summarize ~/Downloads/foo.pcap and show me the top TCP conversations"*
- *"capture 200 packets from wlan0 and tell me what protocols are on the wire"*

### Manual registration (if you don't want the script)

```bash
claude mcp add wireshark --scope user \
  -- /home/user/Documents/Github/downIoads/WiresharkMCP/.venv/bin/python \
     -m wireshark_mcp

codex mcp add wireshark -- \
  /home/user/Documents/Github/downIoads/WiresharkMCP/.venv/bin/python \
  -m wireshark_mcp
```

## Registering with Claude Desktop

Edit `~/.config/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "/home/user/Documents/Github/downIoads/WiresharkMCP/.venv/bin/python",
      "args": ["-m", "wireshark_mcp"]
    }
  }
}
```

## Safety guardrails

- **Sandbox**: all writes go to `~/.wireshark-mcp/captures/` — path traversal rejected
  ([runner.py:44-51](wireshark_mcp/runner.py#L44-L51))
- **Bounded capture**: hard caps of 100k packets / 300s, both required
  ([server.py:23-24](wireshark_mcp/server.py#L23-L24))
- **Output size cap**: 5 MB stdout cap on every subprocess
  (env: `WIRESHARK_MCP_MAX_OUTPUT`)
- **No shell**: subprocess uses argv, never `shell=True`
- **Timeouts**: 60s default; capture timeout = duration + 10s

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `WIRESHARK_MCP_BIN_DIR` | unset (use `$PATH`) | dir containing tshark/dumpcap/etc. |
| `WIRESHARK_MCP_CAPTURE_DIR` | `~/.wireshark-mcp/captures` | sandbox for writes |
| `WIRESHARK_MCP_DISSECTOR_DIR` | `~/.wireshark-mcp/dissectors` | where `write_dissector` stores Lua dissectors |
| `WIRESHARK_MCP_MAX_OUTPUT` | `5242880` (5 MiB) | per-call stdout cap |

## Permissions note

If `list_interfaces` or `capture` fail with `dumpcap: Permission denied`, your
shell is not in the `wireshark` group yet. Either log out / log back in, or
`newgrp wireshark` in a new terminal before launching the MCP-using client.

```bash
getcap /usr/local/bin/dumpcap
# should print: /usr/local/bin/dumpcap cap_net_admin,cap_net_raw=eip
```

## Development

```bash
cd /home/user/Documents/Github/downIoads/WiresharkMCP
.venv/bin/pip install -e .
.venv/bin/python -m wireshark_mcp      # speaks MCP over stdio; ctrl-C to stop
```

Quick smoke test in Python:

```python
from wireshark_mcp import server
print(server.pcap_info("/path/to/your.pcap"))
```
