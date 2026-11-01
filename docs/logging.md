# Rust router logging

`snusnu-router` writes logs to standard error. Each record has a UTC RFC 3339
timestamp, severity, module target, message, and relevant structured fields.
The default level is `info` and the default format is human-readable text.
Set `SNUSNU_LOG_FORMAT=json` for one JSON record per line. Invalid format or
`RUST_LOG` values stop startup with an error.

| Level | What it records |
| --- | --- |
| `error` | Terminal router failures. |
| `warn` | Link timeouts, reconnects and delays, rejected or withdrawn routes, and backpressure. |
| `info` | Router and LLC startup, upstream connection and server-owned identity, CP route publication, circuit open/close, and LLC state changes. |
| `debug` | Every accepted Ethernet and WebSocket circuit packet, including a full hex dump and decoded fields. |
| `trace` | Ignored frames, queue and timer details, and other high-volume internal steps. |

Use the standard `RUST_LOG` filter to select a level. `RUST_LOG=debug` enables
debug records globally; `RUST_LOG=snusnu_router=debug` limits them to the router
binary. The filters can be narrowed further to module targets, for example
`RUST_LOG=snusnu_router::endpoint=debug,snusnu_router=info`.
Prefer the scoped filter when packet debugging; a global filter can also
enable logs from WebSocket and TLS dependencies.

Packet records include ingress or egress direction and the local interface or
route port. Ethernet records show source and destination MAC addresses,
802.3 length, SAPs, command/response bit, LLC control type, sequence and
acknowledgement numbers, and poll/final when present. XID/TEST records retain
their exact information bytes. SNA information records include their byte
length and decoded transmission and request/response header fields when the
bytes can be parsed safely. A segment or unknown format is identified as such;
the router does not claim to decode an entire application message from one
LLC frame. WebSocket records include the upstream host, resolved IP and port, server-owned
router and connection identifiers, CP route names, circuit ID, and credit
values where relevant. The bearer credential is never logged.

For a local lab run with debug logs:

```sh
umask 077
export RUST_LOG=snusnu_router=debug
export SNUSNU_LOG_FORMAT=json
sudo --preserve-env=RUST_LOG,SNUSNU_LOG_FORMAT \
  target/debug/snusnu-router --lab-link sol5 sol4 \
  02:00:35:27:23:01 02:00:35:27:23:02 >>router.jsonl 2>&1
```

For `--remote-link`, export `SNUSNU_ROUTER_TOKEN` separately and include it in
the `sudo --preserve-env` list. The router logs the upstream host and port, not
the credential. Use `RUST_LOG=info` for normal operation.

Debug hex dumps can contain SNA sign-on data, screen contents, and other
application data. Restrict access to captured files, rotate and delete them
according to the site's retention policy, and share excerpts only after
checking their contents. Text and JSON output both go to standard error; the
router does not rotate files itself.
