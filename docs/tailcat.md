# Tailcat hosts

WebSSH can reach an SSH server through [tailcat](https://github.com/tailscale/tailcat),
Tailscale's "netcat over the Tailscale data plane". A tailcat server needs no
open inbound port, no Tailscale account and no root: it prints an address
(`tc...`), and anyone who has that address can dial a port behind it, over
WireGuard, relayed through DERP until NAT traversal finds a direct path.

Plain SSH is unchanged. A Tailcat host is another entry in the host list, and
the connect form offers it alongside the others.

WebSSH is built and tested against tailcat **v0.7.0**, the version the container
image ships. tailcat is experimental and makes no stability promises for its CLI
or wire format, so WebSSH logs a warning at startup if the binary reports any
other version.

## How it works

For each connection, WebSSH runs `tailcat --key=<key> <address> <port>` as a
child process and speaks SSH over its stdin and stdout. This is the same thing
`tailcat ssh` does with OpenSSH's `ProxyCommand`. Every connection gets its own
process. The process is stopped (SIGTERM, then SIGKILL) and reaped when the
session closes, when connecting fails, or when the worker is recycled.

On the server side, any of these work:

```sh
# tailcat's built-in SSH server, no SSH authentication: the address is the credential
tailcat serve no-auth-ssh

# tailcat's built-in SSH server, public keys required
tailcat serve --ssh-authorized-keys=~/.ssh/authorized_keys ssh

# forward to the machine's real sshd, and only accept one tailcat client identity
tailcat serve --allow=nodekey:<public key> 22
```

For a stable address, create the server key once with `tailcat genkey --key=default`.
Without a saved key, the address changes every time the server restarts.

Logging in works as it does for any host: password, uploaded key, stored key, or
TOTP. A `no-auth-ssh` server accepts SSH's "none" method, which WebSSH tries for
Tailcat hosts when no password or key is given. The username field is still
required by the form, but such a server ignores it.

## Where each kind of host is configured

There are two separate surfaces, and they are not equivalent:

| | Administrator hosts | User hosts |
|---|---|---|
| Where | `config.yaml` (`hosts:`), on the server's disk | Settings tab in the web UI |
| Who | whoever can edit the server's config file | each signed-in user, for themselves only |
| Applies to | every user | only the user who saved it |
| Can name server files (`tailcat_key`, `tailcat_address_file`) | yes | no |

**WebSSH has no web page for editing administrator configuration.** WebSSH has
no administrator role at all; it knows only the username header the auth proxy
sends. Any web editor for `config.yaml` would let every signed-in user rewrite
the allowlist. Administrator configuration therefore stays a file that only
someone with access to the server's filesystem can change.

Changes to `hosts:` (Tailcat entries included) are picked up within about 5
seconds, without a restart. A reload that fails validation is logged and
ignored, and the previous host list stays in effect. `user_tailcat_hosts` and
the `tailcat:` block are read only at startup, so changing them needs a
restart. A restart drops live sessions.

## Administrator hosts

Add entries with `transport: tailcat` to `hosts:` in the config file:

```yaml
hosts:
  - name: "Lab box"
    transport: tailcat
    tailcat_address: "tcXXXXXXXX..."       # or tailcat_address_file, below
    port: 22                               # port behind the tailcat server; default 22
    # Optional: present this client identity, for servers that use --allow.
    # The JSON file `tailcat genkey --client --key=/path/x.private.json` writes.
    tailcat_key: /data/tailcat/lab-client.private.json
    # Optional: pin the SSH host key, as for any host.
    host_key: "ssh-ed25519 AAAA..."

  - name: "Build server"
    transport: tailcat
    # Keep the address out of config.yaml, e.g. in a Docker secret.
    tailcat_address_file: /run/secrets/build-tailcat-address

tailcat:                    # all optional
  binary: /usr/local/bin/tailcat   # default: "tailcat" on PATH
  timeout: 30                      # seconds to set up a connection
  derpmap_url: https://derp.example.com/derpmap.json  # your own relays
  state_dir: /data/tailcat         # tailcat's private cache/config dir
```

* A Tailcat entry has no `hostname`, and setting one is an error.
* `tailcat_key` and `tailcat_address_file` must be absolute paths. Both are
  read and checked when the config loads, and again on every reload, so a bad
  file stops the config from loading instead of failing at connect time.
* Keep both files readable only by the WebSSH user (`chmod 600`), and keep
  `config.yaml` itself private if it holds an address.

### The allowlist

`hosts:` stays an allowlist. Tailcat entries change it only in these ways:

* A Tailcat host can only be reached through its own entry. The connect form
  sends an opaque handle (`tailcat:<id>`), never an address, and nobody can type
  an arbitrary tailcat address into the form.
* Tailcat entries count as configured hosts. A `hosts:` list that contains only
  Tailcat entries therefore allows **no** plain SSH destinations, the same as any
  other non-empty allowlist.
* Without `hosts:`, plain SSH stays free-form as before. Tailcat still needs an
  entry.

## User hosts

With `user_hosts: true` **and** `user_tailcat_hosts: true`, users can add Tailcat
hosts in Settings → Hosts by choosing "Tailcat" in a row's connection-type menu
and pasting the address the server printed.

```yaml
user_hosts: true
user_tailcat_hosts: true
```

This is off by default and needs its own switch: it lets users reach tailcat
servers that the administrator never listed, beyond what `user_hosts` already
allows.

* **The address is write-only.** After a save, the browser never receives it
  again; the row shows "address saved". Saving the row again without retyping
  the address keeps it. Pasting a new one replaces it.
* Users cannot point WebSSH at files on the server: `tailcat_key` and
  `tailcat_address_file` are rejected in a user's list.
* If `user_tailcat_hosts` is later turned off, saved Tailcat hosts are hidden and
  can't be used to connect, but they are kept on disk. Turning it back on
  restores them.

### Tailcat identity

Settings → Connection → *Tailcat identity* holds one client identity per user:

* **Generate new identity** creates a key on the server.
* **Import key…** takes a file from `tailcat genkey --client` or a bare
  `privkey:...` line.
* **Delete** removes it.

Only the public half (`nodekey:...`) is ever shown. Add it to a server with
`tailcat serve --allow=nodekey:...`, then tick "use my Tailcat identity" on that
host's row. Hosts without the tick connect with a fresh throwaway key, which is
what a server without `--allow` expects.

The key is stored at `<userdatadir>/<user>/tailcat-identity.private.json`, mode
0600, in the form tailcat itself reads.

## Security notes

* **An address is a credential.** It contains a WireGuard pre-shared key. Against
  a `no-auth-ssh` server, knowing it is enough for a shell. WebSSH:
  * never sends an administrator's address to the browser (not in the page, not
    in `/api/hosts`, not in the Settings pane);
  * sends a user's address back to nobody, including that user;
  * keeps addresses out of log lines and error messages (hosts are logged as
    `tailcat:<id>` plus their name);
  * strips anything shaped like an address or private key from tailcat's
    stderr before logging it.
* **Prefer servers that authenticate clients.** Use `--allow` (tailcat identity)
  or `--ssh-authorized-keys` (SSH keys). An identity key is a second factor
  beyond the address: a leaked address alone is not enough.
* **Server identity.** The address pins the server's WireGuard public key, so
  the tunnel itself proves who the server is. That is why, for Tailcat hosts,
  WebSSH does not consult `known_hosts`, does not apply `policy`, and never
  writes to `known_hosts`. A `host_key` pinned on the entry is still enforced.
  Pin one if you want the SSH host key checked as well.
* **The child process gets a minimal environment.** `HOME` and the XDG
  directories point at `state_dir`, and only proxy, locale and CA variables are
  passed through. In particular, no `TAILCAT_*` or `TS_*` variables reach it.
  `--key` is always passed, so a stray `client-default` key in some config
  directory is never picked up.
* **The relays are shared.** tailcat's default DERP relays are free,
  rate-limited and come with no SLA. Use `derpmap_url` to point at relays you
  run. Direct paths need outbound UDP from the container; without it, traffic
  stays on the relay over HTTPS.
* **tailcat's own security model** assumes the same person runs both ends (see
  its SECURITY.md). Only add tailcat servers you trust.

## The container image

The Dockerfile downloads the v0.7.0 release tarball for the build architecture
(amd64, arm64 or armv7). It checks the tarball against SHA-256 sums copied from
the release's `checksums.txt`, then checks that `tailcat --version` reports
`v0.7.0`. A changed or tampered download fails the build. To upgrade, change
`TAILCAT_VERSION` and all three sums together, then run the tests below against
the new binary.

## Tests

* `pytest tests/test_tailcat.py` covers parsing, secret handling, the allowlist,
  the user API and identity keys, and the child-process lifecycle, using
  `tests/fake_tailcat.py`. That stand-in connects to the test SSH server, so no
  network is needed.
* `TAILCAT_BIN=/path/to/tailcat pytest tests/test_tailcat.py` also runs the
  real binary end to end over loopback, using tailcat's in-process DERP relay
  (`TS_DEBUG_TAILCAT_LOCAL_DERP`). It checks:
  * a `no-auth-ssh` session;
  * an `--allow` server that admits WebSSH's identity and ignores an ephemeral
    key;
  * that WebSSH's public key matches `tailcat genkey --client`.

  These tests start a short-lived `no-auth-ssh` server as the current user,
  reachable only through an address that never leaves the test's temporary
  directory.
* `node --test tests/js/*.test.js` covers the settings-pane payloads.
