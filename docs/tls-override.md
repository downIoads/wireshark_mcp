# TLS / CA-override

Reference table for getting opaque app runtimes to trust mitmproxy's CA cert
(`~/.mitmproxy/mitmproxy-ca-cert.pem`) so `mitm_start` can decrypt their TLS.

The baseline — apps that read the OS trust store — works after one-time:

```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem \
        /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

Use this page when that's not enough. Symptom of "not enough": mitm's log
shows `Client TLS handshake failed ... tlsv1 alert unknown ca` (or similar)
for the target app, even after `update-ca-certificates`. That means the
runtime ships its own bundle or pins, and you need a runtime-specific hook.

The fastest diagnostic is `mitm_flows(handle, flow_type="tcp")` — if a flow
reaches `server_conn.tls_established=false` for the target host while
other apps work, the runtime is ignoring the system store.

## Quick lookup

| Runtime / engine | Reads OS store? | Hook | Notes |
|---|---|---|---|
| **Linux native / glibc + OpenSSL** | yes | `update-ca-certificates` | The baseline. covers most CLI tools, curl, wget, Python `ssl`, Go w/ cgo. |
| **Go (pure-Go TLS, `CGO_ENABLED=0`)** | yes (reads `/etc/ssl/certs/ca-certificates.crt`) | `update-ca-certificates`; override with `SSL_CERT_FILE=/path` | Bundled binaries often have `CGO_ENABLED=0`. The Go `crypto/x509` package walks a hardcoded list of paths — system update is enough on Debian/Ubuntu. |
| **Python `requests` / `httpx`** | no (uses `certifi`) | `REQUESTS_CA_BUNDLE=/path/to/system+mitm.crt` (requests) or `SSL_CERT_FILE` (httpx) | `certifi`'s bundle is shipped with the wheel; env var redirects without rebuilding. |
| **Node.js** | no (compiled-in Mozilla bundle) | `NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem` | Appends, doesn't replace — safest option. Works for Electron's main process too. |
| **Electron / Chromium (Linux)** | yes for renderer net stack (uses `nss` → system store) | `update-ca-certificates` covers it; for main-process Node calls, also set `NODE_EXTRA_CA_CERTS` | Some apps (Discord, Slack) use the Chromium net stack and Just Work after `update-ca-certificates`. The asar-bundled Node bits don't. |
| **Java (JRE / JDK)** | no (uses `cacerts` keystore) | `keytool -importcert -trustcacerts -alias mitm -file ~/.mitmproxy/mitmproxy-ca-cert.pem -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit` | Per-JDK install. Some apps bundle their own JRE — find it via `ps -p <pid> -o exe`, then point `keytool` at *that* JRE's `lib/security/cacerts`. |
| **Mono / Unity (Mono)** | no (uses `~/.config/.mono/certs/` via `mono-cert-sync`) | `cert-sync --user /etc/ssl/certs/ca-certificates.crt` after `update-ca-certificates` | Older Mono. Unity games built against IL2CPP may use BoringSSL instead — see IL2CPP row. |
| **Unity (IL2CPP) / native BoringSSL** | sometimes — depends on the build | Engine-specific; try `SSL_CERT_FILE` first | Many IL2CPP builds statically link a vendored cert bundle. No clean override; you may need to swap the bundle in the binary or use a custom `UnityWebRequest` CA callback if the game ships one. |
| **Godot 3** | no | Per-game `override.cfg` next to the binary; see below | The cleanest engine override — Godot exposes `network/ssl/certificates` as a project setting. |
| **Godot 4** | no | Same `override.cfg` mechanism; key is `network/tls/certificate_bundle_override` | Renamed setting; otherwise identical to Godot 3. |
| **Rust `rustls` (vendored roots)** | no | `SSL_CERT_FILE=/path/to/system+mitm.crt` if app uses `rustls-native-certs`; otherwise no clean override | If the app uses pure `rustls` with `webpki-roots`, the bundle is compiled in and you can't add a CA without rebuilding. |
| **curl (system binary)** | yes (links system OpenSSL/GnuTLS) | `update-ca-certificates` | Confirm with `curl-config --ca`. |
| **Game-launcher clients + games launched through them** | yes (most launchers use system OpenSSL via dynamic linker) | `update-ca-certificates` | The launcher process itself trusts the system store. Note: `mode local:` matches the immediate process basename — many launchers use shell-script wrappers, so target the eventual child binary, not the launcher script. |

## Recipes

### Godot 3 / 4

Drop an `override.cfg` next to the game binary:

```ini
# Godot 3
[network]
ssl/certificates="/path/to/system+mitm.crt"

# Godot 4
[network]
tls/certificate_bundle_override="/path/to/system+mitm.crt"
```

…where the merged bundle is:

```bash
cat /etc/ssl/certs/ca-certificates.crt \
    ~/.mitmproxy/mitmproxy-ca-cert.pem \
  > /path/to/system+mitm.crt
```

Must include the system roots too — Godot replaces, not appends. The
file path can be absolute or relative to the binary.

### Java / JVM apps

```bash
# Find the JRE the app uses (not your $JAVA_HOME — bundled JREs are
# common for desktop Java apps).
JRE=$(readlink -f /proc/$(pgrep -n java)/exe | xargs dirname | xargs dirname)

sudo keytool -importcert \
  -trustcacerts \
  -alias mitmproxy \
  -file ~/.mitmproxy/mitmproxy-ca-cert.pem \
  -keystore "$JRE/lib/security/cacerts" \
  -storepass changeit \
  -noprompt
```

Per-app JREs are common (Minecraft, JetBrains IDEs, many Java desktop
apps ship their own). Per-user override: copy the cacerts to a writable
location, modify it, then point the app at it with
`-Djavax.net.ssl.trustStore=/path/to/cacerts` if the launcher accepts
JVM args.

### Node.js / Electron main process

```bash
NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem your-app
```

For Electron apps installed system-wide, edit the `.desktop` entry's
`Exec=` line to prepend the env var, or wrap the launcher.

### Python `requests` / `httpx`

```bash
# requests
export REQUESTS_CA_BUNDLE=/path/to/system+mitm.crt

# httpx (and most other Python TLS that respects OpenSSL env vars)
export SSL_CERT_FILE=/path/to/system+mitm.crt
```

### Mono (Unity legacy builds)

```bash
sudo update-ca-certificates  # if not done already
cert-sync --user /etc/ssl/certs/ca-certificates.crt
```

If the Unity build is IL2CPP, this won't help — see the next section.

### Unity IL2CPP / vendored BoringSSL

There's no clean per-app hook. Options in order of effort:

1. **Check if the game uses `UnityWebRequest`** with a custom
   `CertificateHandler`. If yes, the game's own code decides what to
   trust — no environment override will work. You'd need to patch the
   game.
2. **Try `SSL_CERT_FILE`** anyway — some IL2CPP builds with mbedTLS
   respect it.
3. **Swap the embedded cert bundle.** IL2CPP games sometimes embed
   `cacert.pem` or `roots.pem` in `*_Data/Resources/` — replace with
   your `system+mitm.crt` and verify with `strings` / hash check.
4. **Hook at the syscall layer.** If the goal is just to see plaintext,
   bypass the cert issue entirely: use `mitm_start` for the network
   trace and `frida-trace` to dump pre-encrypt buffers from the
   BoringSSL `SSL_write`/`SSL_read` symbols.

### Verifying a CA hook worked

```python
# After applying the engine-specific hook and relaunching the app:
mitm_flows(handle, flow_type="tcp")
# Look at the flows for the target host. If client_conn.tls_established
# stays false and the flow closes immediately, the cert is still being
# rejected. If you start seeing matching HTTP flows for the same host,
# you're in.
```

Confirm with `mitm_flow_body(handle, flow_id, "response")` — if you can
read a plaintext response body, TLS is decrypted end-to-end.

## When to extend this table

Every time you sink more than 15 minutes into "why won't this app trust
mitm?", add the engine + the hook you found here. The cost of writing
two lines now is much less than re-deriving the same hook in three
months.
