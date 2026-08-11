# File Transfer — Design

Move files between the browser and the host a user is already connected to,
without a second login and without leaving the terminal.

## Goal

A user working in a WebSSH terminal can drag a file onto it to upload, and use
a download button to pull a file back. Transfers reuse the SSH connection the
terminal is already running on, so they need no additional credentials and
carry exactly the permissions of the SSH user.

## Scope

In scope:

- Upload by dropping a file on the terminal.
- Download by path, and by picking from a listing of one directory.
- Files up to a few hundred megabytes, streamed in both directions, with
  progress and cancel.
- Available to anyone with a terminal session. The feature itself has no
  configuration gate. (A config flag exists for shell injection only — it
  controls automatic destination detection, never whether transfers work.)

Out of scope:

- A general file browser: no navigation, rename, delete, or chmod.
- Resume after failure. A broken transfer is restarted, not continued.
- Transfers that outlive the terminal session that started them.
- Directory or multi-file transfers. One file at a time, each drop its own
  transfer.

## Why SFTP on the existing connection

SSH multiplexes channels, so `worker.ssh.open_sftp()` opens a file-transfer
channel on the connection the terminal already authenticated. No second login,
no stored credentials, and the remote end enforces the same permissions it
already does for the shell.

Two alternatives were considered and rejected:

- **Framing file bytes over the existing WebSocket.** Avoids new endpoints, but
  a download must accumulate in JavaScript memory to become a Blob, which fails
  the few-hundred-megabyte target. The File System Access API avoids that but
  is Chromium-only. It also puts bulk transfer in contention with keystrokes on
  one channel.
- **A second SSH connection per transfer.** Perfect isolation, but WebSSH
  deliberately does not retain the password past the connect POST, so it would
  have to re-prompt. That is the opposite of the goal.

## Architecture

### `webssh/transfer.py` (new)

All SFTP mechanics, with no Tornado or HTTP knowledge. It takes a paramiko
client, a path, and a chunk sink, and moves bytes. Keeping it free of web
concerns is what lets the bulk of the logic be tested against a stub SFTP
client, in the same spirit as `user_data.py` being separable from `handler.py`.

Responsibilities: opening and closing SFTP channels, chunked read and write,
cancellation, partial-file cleanup, overwrite detection, directory listing, and
translating paramiko errors into a small set of typed failures.

### Live-worker registry

Once the WebSocket claims a worker, `handler.py:936` sets
`workers[worker_id] = None`; the worker survives only because the IOLoop holds
it as a callback, reachable through a `weakref` on the handler. There is
therefore no way to find a live worker by ID, which the transfer handlers need.

Add a `live_workers` dict in `worker.py` alongside `clients`, populated when the
WebSocket attaches and cleared in `Worker.close()`.

This is deliberately a second structure rather than a change to `clients`. The
null-out is what makes a worker ID single-use for WebSocket authentication;
weakening it to make lookup convenient would let a leaked ID open a second
terminal on the same session.

### Handlers (`webssh/handler.py`)

| Route | Method | Purpose |
| --- | --- | --- |
| `/transfer/download` | GET | Stream a remote file to the browser |
| `/transfer/upload` | POST | Stream a request body to a remote file |
| `/transfer/list` | GET | List one directory, for the download picker |

A shared mixin resolves worker ID plus client IP to a live worker, or raises
404. Transfers are reachable exactly where the terminal is: same client-IP
check, same 32-byte worker token. A transfer is never more reachable than the
session it belongs to.

Paramiko's SFTP calls block, so every one of them runs on the existing
`ThreadPoolExecutor`, never on the IOLoop.

### Client

`webssh/static/js/file-transfer.js` (new) holds pure logic with no DOM or jQuery
access, following the `user-hosts.js` precedent so it is unit-testable under the
`node --test` harness: OSC 7 URI parsing, resolution of relative paths against
the current directory, and byte formatting.

DOM wiring — drop zone, progress tray, picker dialog — goes in a separate file
rather than into `main.js`, which is already 2007 lines and would pass 2400 with
this feature inlined.

### Tracking the working directory

`main.js` registers an OSC 7 handler through xterm's
`parser.registerOscHandler(7, ...)`. The browser owns the current directory and
sends a fully-resolved absolute path with every request. The server never infers
a destination.

To make shells emit OSC 7, WebSSH writes a `PROMPT_COMMAND` (bash) or `precmd`
(zsh) snippet into the shell at session start. This is the least robust part of
the design: it must branch on shell family, it is briefly visible before being
cleared, and on an unexpected shell it prints junk.

It is therefore gated behind a config flag defaulting to on, and the editable
path box is always available as a fallback. Turning injection off costs
automatic destination detection, not the feature.

## Data flow

### Upload

1. A drop resolves the destination from the tracked OSC 7 directory, or opens
   the path box if no directory is known.
2. `fetch('/transfer/upload?id=...&path=...', {method: 'POST', body: file})`.
   The `File` object streams; it is never read into a string.
3. `@stream_request_body` delivers chunks to `data_received`, which hands each
   to the executor for `sftp_file.write()` and **returns that Future**. Tornado
   stops reading the socket until the write lands, so a slow host throttles the
   browser instead of growing server memory.
4. On completion the handler closes the SFTP file and returns JSON with the
   final path and byte count.

If the destination is an existing directory, the source filename is appended.

#### Overwrite

The request carries `overwrite=false` by default. The handler stats the
destination *before* opening it for writing, and if it exists returns **409
Conflict** immediately, while almost none of the body has been sent. The client
then asks once — Overwrite, Rename, or Cancel — and reissues the request with
either `overwrite=true` or a new `path`.

This costs a second request rather than a pre-flight stat on every upload, and
it keeps the existence check on the same code path that does the open, rather
than in a separate round trip that could race with it. Silently clobbering a
remote file because someone dropped onto the wrong terminal is not recoverable,
which is what justifies the extra round trip in the rare colliding case.

### Download

1. The picker calls `/transfer/list`, which returns one directory's entries
   (name, size, is_dir, mtime) with the path box prefilled from OSC 7.
   Directories appear in the listing but are not selectable and cannot be
   clicked into — changing directory means editing the path box. Navigation is
   what separates this from the file browser that is out of scope.
2. `/transfer/download` sets `Content-Disposition: attachment` and streams
   fixed-size chunks, each `self.write()` followed by `await self.flush()`.
   The flush is the backpressure point against a slow browser.

Transfers use their own chunk size of 256 KB, not `worker.BUF_SIZE`. That
constant is 32 KB and tuned for interactive terminal latency; bulk SFTP
throughput wants larger reads.
3. The browser's own download manager writes to disk. Nothing accumulates in
   JavaScript memory.

Downloads call `SFTPFile.prefetch()`. Sequential reads are dramatically faster
with it, and it is the largest throughput lever available.

### Cancel

Cancellation is connection teardown, not a protocol message. `AbortController`
drops the connection, Tornado fires `on_connection_close()`, and the handler
sets a flag the chunk loop checks before its next iteration.

A cancelled or failed upload deletes the partial file. A truncated file sitting
under the real name is worse than no file at all.

### Session interaction

- **Idle timeout.** `handler.py:945` only resets on WebSocket messages, so a
  long download with no typing would disconnect the terminal underneath it.
  Each active transfer increments a counter on the worker, and a nonzero
  counter suppresses the idle disconnect.
- **Concurrency.** Transfers do not count against `maxconn`, since they open no
  new SSH connection. Concurrent transfers per worker are capped at 3 so a
  stack of drops cannot exhaust channels on the remote sshd.
- **Tab close cancels.** Transfers are scoped to the session that owns them.
  This keeps the feature an overlay on the terminal rather than a background
  file service.

## Error handling

### Remote errors are surfaced verbatim

PR #29 established that server-state errors must never reach the client
(`handler.py:145`), because they leak paths and configuration from the WebSSH
host. SFTP errors are categorically different: they describe the *user's own*
filesystem, reached with their own credentials, through a shell where the same
information is one `ls` away. They are passed through unchanged.

This distinction is load-bearing and easy to mistake for a bug. Do not
"harden" these into generic 500s.

| Condition | Response |
| --- | --- |
| `EACCES` / `EPERM` | 403, message passed through |
| `ENOENT` | 404 |
| Path is a directory (download) | 400 |
| Upload destination exists, `overwrite=false` | 409 |
| `ENOSPC` | 507, message passed through |
| Worker gone or SSH dropped | 410, "terminal session ended" |
| Concurrency cap exceeded | 429 |

### No path jailing

Paths are not sanitized, filtered, or chrooted. The security boundary is the
SSH user's own Unix permissions — the same boundary the terminal already
enforces. A path filter would break legitimate absolute-path use while offering
only the appearance of protection, since the user can already reach any of it
from the shell.

Stated explicitly because the absence of a traversal check reads as an
oversight otherwise.

### Encoding

- Remote filenames are not necessarily UTF-8. `Content-Disposition` uses RFC
  5987 `filename*=UTF-8''...` with an ASCII `filename=` fallback. Filenames
  containing CR or LF are rejected rather than encoded, closing a header
  injection vector.
- Directory listings cap at 1000 entries and report truncation, so a large
  directory cannot produce a multi-megabyte JSON response.

### Mid-transfer session loss

If the terminal's SSH connection drops while a download streams, the SFTP
channel dies with it. The chunk loop catches the failure, stops, and closes the
response early. The browser then reports a failed download, which is honest.
Padding the response to the promised `Content-Length` would hand the user a
silently corrupt file.

## Testing

`tests/sshserver.py` implements shell, exec, and PTY requests but **no SFTP
subsystem**. That constraint drives a three-layer split.

### 1. `transfer.py` against a stub SFTP client

A stub implementing `open`, `stat`, `listdir_attr`, and `remove` covers the
logic exhaustively and without a network: chunking, cancel mid-stream,
partial-file cleanup, overwrite detection, directory-destination handling, and
the errno-to-failure mapping.

### 2. Handlers, with SFTP mocked at the `open_sftp()` seam

Real Tornado requests through the real routes, with `worker.ssh.open_sftp`
patched. This layer pins:

- Worker-ID plus client-IP resolution, **including that a valid ID from a
  different client IP gets 404** — the security property the endpoints rest on.
- 410 when the worker is gone; 429 past the concurrency cap; 409 on an
  existing destination, and success when the request is reissued with
  `overwrite=true`.
- `Content-Disposition` encoding for a non-ASCII filename, and rejection of a
  filename containing a newline.
- That `data_received` returns a Future rather than buffering, which is what
  makes backpressure real.
- The idle-timeout counter suppressing disconnect during a transfer and
  releasing afterwards.

New test classes use `override_options` from `c65fbed` rather than hand-rolled
option restoration.

### 3. `file-transfer.js` under `node --test`

Extends the harness from #29 with `tests/js/file-transfer.test.js`: OSC 7 URI
parsing (percent-decoding, the `file://host/path` form, malformed sequences),
relative-path resolution, and byte formatting. The dependency-free constraint
holds; no new npm packages.

### Manual verification

Shell injection is not automated. Whether the snippet cleanly emits OSC 7 across
bash, zsh, and dash, and how visible the injection is, can only be judged
against real shells. Verify on the dev stack at `/opt/stacks/webssh-dev`:

- bash and zsh: directory tracked, injection not visibly disruptive
- dash or another unexpected shell: degrades to the path box without garbage
- `su` to another user: tracking stops, path box takes over
- A ~300 MB file each way: progress advances, cancel works, memory on the
  WebSSH container stays flat

### Adding SFTP to the test server was considered and rejected

It would mean implementing enough of the SFTP protocol to be trustworthy, and a
buggy fake server produces false confidence. Mocking at `open_sftp()` tests the
code we control.

## Style constraints

Match the surrounding code, as `user_data.py` was written to match
`user_keys.py`:

- No f-strings; use `.format()`.
- `super(ClassName, self)` form.
- Compact parenthesised import blocks.
- JavaScript stays ES5: no `const`, `let`, arrow functions, or template
  literals. CI lints this.
- CI pins `ruff==0.15.6`; do not modernise incidentally.
