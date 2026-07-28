# User-Editable Host List and Roaming Settings

**Date:** 2026-07-27
**Status:** Approved design, pending implementation

## Problem

The host list lives in `config.yaml` and only an administrator with filesystem
access can change it. A signed-in user cannot add a machine of their own. User
preferences fare no better: the last-used hostname, username, and per-host
default command sit in `localStorage`, so they vanish when the user switches
browsers or machines, and terminal appearance is settable only through URL query
parameters.

This design lets each authenticated user maintain a private host list and a set
of preferences, both stored on the server so they roam across sessions.

## Scope

In scope: per-user host records, per-user preferences, a settings tab, and the
server-side storage and API behind them.

Out of scope: administrator editing of `config.yaml` through the web UI, sharing
host lists between users, and any change to how credentials are handled.
Passwords, TOTP codes, and key passphrases remain client-side only and are never
written to server storage.

## Identity and Gating

A user is identified by the `userheader` HTTP header (`X-Authentik-Username` by
default), the same mechanism that already scopes per-user SSH keys.

Two new configuration keys:

```yaml
user_hosts: true                          # default false
userdatadir: /var/lib/webssh/user-data    # optional; defaults to userkeydir
```

The feature is active only when all three conditions hold:

1. `user_hosts` is true,
2. a data directory resolves (`userdatadir`, or `userkeydir` as fallback), and
3. the request carries a valid username in the configured header.

When inactive, `/settings-pane` returns 404, the APIs return 403, and the gear
control is not rendered. Behavior for existing deployments is unchanged.

`userdatadir` defaults to `userkeydir` so that a deployment already using
per-user keys needs no new configuration; the JSON files land in the same
per-user directory as `id_ed25519`.

At startup, enabling `user_hosts` without `trusted_proxies` logs the same
spoofable-header warning that `userkeydir` already emits.

## Storage

A new module, `webssh/user_data.py`, sits alongside `user_keys.py` and reuses its
`sanitize_username` and path-traversal guard:

```
<userdatadir>/<username>/hosts.json
<userdatadir>/<username>/settings.json
```

Writes go through `tempfile` plus `os.rename` at mode `0600`, matching the
atomic-write pattern in `user_keys.py`. Each file carries a `"version": 1` field
so a later schema change has somewhere to hook. A missing file reads as empty. A
corrupt or unparseable file is logged and also reads as empty; it never raises to
the request handler and never blocks a connection.

Public surface:

- `read_hosts(dir, user)` / `write_hosts(dir, user, hosts)`
- `read_settings(dir, user)` / `write_settings(dir, user, settings)`
- `validate_hosts(hosts)` / `validate_settings(settings)`, raising `ValueError`

Concurrency is last-write-wins per user. Two browser tabs editing the same user's
list simultaneously is not a case worth locking for.

## Host Model

A user host record:

```json
{
  "name": "homelab",
  "hostname": "nas.lan",
  "port": 2222,
  "host_key": ["ssh-ed25519 AAAA..."],
  "username": "ryan",
  "default_command": "tmux attach || tmux new"
}
```

`name`, `hostname`, `port`, and `host_key` are validated by the same code path as
administrator hosts. The per-entry validation currently inside
`parse_allowed_hosts` is extracted into a shared `parse_host_entry` so a user
cannot submit a malformed key pin that an administrator could not.

`username` and `default_command` are user-only fields. They prefill the connect
form when the host is selected and are ignored on administrator entries.

## Allowlist Semantics

`hosts:` in `config.yaml` is a security allowlist, not a bookmark list. Making it
user-editable would silently dissolve that control, which is why the feature is
opt-in.

At connect time, `check_allowed_hosts` and `load_configured_host_key` consult the
administrator hosts merged with the requesting user's hosts. Two rules govern the
merge:

- Administrator entries win on a `hostname:port` collision, so a user cannot
  override a pinned production host key.
- When `user_hosts` is false, only administrator hosts are consulted, and a
  user-supplied host outside the allowlist is rejected exactly as today.

Personal hosts carry their own `host_key` pin. This is what makes them usable
under `policy: reject`, where an unpinned host cannot connect at all.

When no administrator allowlist is configured, the hostname field remains
free-text as it is today, and personal hosts act purely as saved bookmarks.

## API

A new `UserDataHandler` in `webssh/handler.py`, modeled on `UserKeyHandler`: the
same `get_auth_username()` helper and the same 401 and 400 responses. XSRF
protection applies, since `xsrf_cookies` is enabled by default.

| Route           | Method | Behavior                                                     |
| --------------- | ------ | ------------------------------------------------------------ |
| `/api/hosts`    | GET    | `{admin_hosts: [...], user_hosts: [...]}`, admin entries flagged read-only |
| `/api/hosts`    | PUT    | Full replacement of the user's list                          |
| `/api/settings` | GET    | The user's settings object                                   |
| `/api/settings` | PUT    | Full replacement of the user's settings                      |

`PUT` validates every entry before writing anything, so a rejected request leaves
stored data untouched. Full-list replacement rather than per-host `POST` and
`DELETE` matches a settings pane with a Save button and keeps the server free of
any opinion about ordering.

## Settings Tab

Settings open as a tab inside the existing WebSSH tab bar, not as a browser
navigation. The application already has a tab system, and reusing it means
opening settings never disturbs a live terminal session.

`tabManager.createTab` gains a `kind` field, `"terminal"` or `"settings"`,
defaulting to terminal. The existing machinery needs little change: `createTab`
already builds a generic pane div, and `activateTab` and `closeTab` already guard
on `tab.term` and `tab.sock` being null, which is exactly the state a settings tab
is in. Three adjustments:

- `activateTab` branches on `kind === "settings"`: hide the shared connect form,
  as it does for a connected terminal, but skip the fit-and-focus path and set
  the page title to "Settings".
- `closeTab`, when the last tab closes, creates a terminal tab rather than
  whatever kind was just closed.
- A settings tab is a singleton. The gear control focuses the existing settings
  tab if one is open and creates one otherwise.

A new `SettingsHandler` serves `/settings-pane`, a `settings.html` Tornado
template rendering an HTML *fragment* — no `<html>` or `<body>` wrapper — which
the client injects into the tab's pane. Keeping the markup in a template matches
how `index.html` is built and avoids introducing a client-side templating layer.
The endpoint is internal and not meant to be navigated to directly.

The pane has three sub-sections:

**Hosts.** Administrator hosts first, greyed and badged read-only, then the
user's editable entries. Each editable row supports add, edit, and delete, with a
textarea for host key pins and a hint pointing at
`ssh-keyscan -t ed25519,rsa <hostname>`.

**Terminal.** Font size, background color, foreground color, cursor color, and
cursor blink. These exist today only as the URL parameters `fontsize`, `bgcolor`,
`fontcolor`, and `cursor`; the page becomes their persistent home. URL parameters
still override stored values, so existing links keep working.

**Connection.** Default encoding, terminal type, and preferred key source
(stored or uploaded).

Because the pane lives in the same document as the connect form, saving changes
calls a `refresh_host_list()` function directly. No cross-document coordination,
no polling, and no reload is needed.

## Client Changes

In `main.js`, `store_items` / `restore_items` and `store_default_command` /
`restore_default_command` become thin wrappers over a small `prefs` object. It
hydrates from a blob that `IndexHandler.get` embeds in the rendered page, which
avoids an extra round trip before the first connect, and issues debounced `PUT`
requests to `/api/settings` on change. The settings pane shares this same
document and therefore the same `prefs` object; it reads current values from it
rather than refetching. `localStorage` is retained as the offline fallback, and as
the sole store when the feature is disabled.

Per-host default commands move from the `command:<hostname>:<port>` keys onto the
host record's `default_command`. A one-time client-side migration copies any
existing `localStorage` values onto matching host records on first load.

Credentials, TOTP codes, and passphrases are excluded from the `prefs` object and
are never transmitted to the settings API.

## Testing

`tests/test_user_data.py`, in the style of `test_user_keys.py`:

- Round-trip read and write for hosts and settings
- Atomic write leaves no partial file on failure
- Missing file and corrupt file both read as empty without raising
- Path traversal via `../` in a username is rejected
- `validate_hosts` rejects malformed ports, missing hostnames, and bad key pins

Additions to `tests/test_handler.py`:

- 403 when the feature is disabled, 401 when the header is absent
- XSRF rejection on `PUT`
- `PUT` with an invalid entry returns 400 and leaves stored data unchanged
- A user host cannot override an administrator host key pin
- With `user_hosts: false`, a user-added host is still rejected by the allowlist

Additions to `tests/test_settings.py` for `userdatadir` resolution, including the
fallback to `userkeydir`, and a `test_app.py` case asserting `/settings-pane`
returns 404 when the feature is off and a fragment when it is on.

The repository has no JavaScript test harness, so the tab behavior is verified
manually: opening settings while a terminal is connected leaves that session
alive, the gear focuses rather than duplicates an open settings tab, closing the
last tab yields a terminal tab, and saving a host updates the connect form's host
dropdown without a reload.

Note for whoever runs the suite: `settings.py` loads the real
`~/.ssh/known_hosts`, so a malformed line in a developer's own file fails 53
unrelated tests. This is an environment issue, not a regression.
