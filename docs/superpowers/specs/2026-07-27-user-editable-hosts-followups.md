# User-Editable Hosts — Deferred Follow-Ups

Findings raised during review of the user-editable-hosts branch that were
deliberately deferred rather than fixed before merge. None blocks merge. They are
recorded here so the judgement is available later; delete this file once it has
been triaged.

Items fixed before merge are not listed. The security defect found by the final
whole-branch review — user host key pins leaking into a process-global paramiko
store — was fixed in `e1b184f` and is covered by tests.

## Correctness

- **Duplicate `known_hosts` appends under `autoadd` + `user_hosts`.** Each request
  now starts from the startup host-key snapshot, so repeat connections to a host
  absent from it re-append an identical line, growing the file unboundedly on a
  busy deployment. Paramiko de-duplicates on load, and this is the security-safe
  direction, so it is cosmetic. Note that `autoadd` plus `user_hosts` is not the
  documented recommendation — the docs recommend `reject` with pinned keys.
- **Quarantine exhaustion.** After 20 `.corrupt` files accumulate for one user,
  `quarantine_file` gives up and leaves the unreadable file in place, which
  re-opens the data-loss path it exists to prevent. Requires 21 separate
  corruption events on one account, each logged at error level.
- **`get_effective_hosts` is called twice per connect POST**, re-reading and
  re-parsing `hosts.json` synchronously on the IOLoop thread. Memoize per request.
- **Non-`ValueError` failures from `_write_json`** (for example `OSError` from
  `os.rename`) propagate as an uncaught 500 through Tornado's default handling.
  No path leak, but the client sees no useful message.
- **`os.write` return value is ignored** in `_write_json`. Regular-file writes do
  not short-write in practice; `os.fdopen`/`f.write` would be more correct.
- **Hostname collision matching is exact-string**, with no case folding. Reviewed
  and judged *not* an invariant break: a user can already add the same machine
  under a different name with their own pin, so case-folding buys nothing.
- **`check_feature_enabled`'s `not self.user_data_dir` clause is dead** as wired,
  since `user_hosts_enabled` already ANDs the directory in.

## Client behaviour

- **`refresh_host_list`'s `$.get` has no `.fail` handler.** On failure the
  hostname field keeps its last known-good state — coherent, but silently stale.
- **A failed `/settings-pane` fetch is permanent.** The tab shows "Failed to load
  settings" and the gear re-focuses that dead tab; only closing it allows a retry.
- **Rows with a blank hostname are silently dropped on save**, with no feedback to
  the user that their half-filled row vanished.
- **A non-numeric port typo is indistinguishable from blank.** `input type=number`
  sanitises `"abc"` to `""`, so it silently defaults to 22. Out-of-range and
  zero/negative values *are* correctly blocked. Detecting the rest needs
  `validity.badInput`.
- **`connect()` from the settings tab creates the terminal tab before form
  validation**, so a connect that then fails validation leaves an empty
  "New Connection" tab behind.
- **`refresh_host_list` side effects.** `trigger('change')` mutates the connect
  form; a stale `current` value can select a different host.
- **`get_xsrf_token` reads the cookie with a regex**, which is more fragile than
  the existing `$('input[name="_xsrf"]').val()` idiom already used elsewhere in
  `main.js`.
- **Residual narrow race in preference flushing.** A connect that arms a new flush
  while the settings pane's PUTs are in flight can be stomped by the pane's
  response rebind. Window is a few hundred milliseconds.
- **`prefs.schedule` arms a pointless 1s timer per connect** when the feature is
  disabled; `flush` then early-returns.
- **`key_source: 'stored'` is applied without checking `has_stored_key`**, and the
  `'upload'` direction is not restored, so a stale preference can produce a
  confusing connect failure.
- **IPv6 hosts do not migrate.** The legacy `command:<host>:<port>` localStorage
  key is split on `:`. Nothing is corrupted; the command simply does not carry
  over. This is a pre-existing key-format limitation.
- **`{% raw json_encode(user_settings) %}`**: Tornado blocks `</script>`
  breakout, but a `<!--<script>` sequence in a stored string can still confuse the
  HTML script-data parser. Self-only — the attacker is the victim.
- **Stored `cursor` beats URL `fontcolor`** as a fallback. Defensible, and as
  specified, but worth knowing.

## Tests

- ~~**`_restore_options` restores 3 of 10 mutated tornado globals**, to hardcoded
  values rather than saved originals.~~ Fixed. `OptionsRestoreMixin.override_options`
  snapshots the previous value of every option a test overrides and restores
  exactly that. `TestSuiteLeavesOptionsClean` pins the invariant; it failed
  against the old code with `policy: ('warning', 'reject')`.
- ~~**A new test class leaves `options.policy = 'reject'` behind** on cleanup.~~
  Fixed with the item above.
- **`OtherTestBase` still restores nothing at all.** It mutates eight globals and
  puts none of them back, so the rest of the suite continues to pass by
  execution-order luck rather than construction. `override_options` is now
  available to it; converting it is the remaining half of this item.
- **Tests leak one `tempfile.mkdtemp` per test method** (about a dozen per run)
  with no cleanup.
- **Coverage gaps**: PUT while the feature is disabled, XSRF on `/api/settings`,
  405 on unsupported verbs, and `admin_hosts` contents are never asserted.
- **Corrupt/wrong-shape read tests cover `hosts.json` only**, not `settings.json`,
  though both share `_read_json`.
- **No dedicated test for the non-numeric-port `ValueError` path**, which was the
  one sanctioned behaviour change in the initial refactor.
- **No JavaScript test harness exists in this repository.** A large fraction of
  this feature is client-side and therefore has no automated coverage; it was
  verified by code review plus three scripted browser passes. Introducing a JS
  harness would be the single largest durable improvement to this feature's
  safety net.

## Lint modernisation backlog

**Resolved (#52).** CI's `lint` job installed `ruff` unpinned, so the 0.16
release turned the gate red across the whole repository without any code
change — 250 errors on `main`, 308 on the user-hosts branch. The job was
pinned to `ruff==0.15.6` while this was deferred. The whole repository has
since been modernized in one deliberate pass and CI is pinned to
`ruff==0.16.4` (updated as later ruff releases are deliberately adopted):

- **`UP032`** — `.format()` calls converted to f-strings.
- **`LOG015`** — every module that logs now has its own
  `logger = logging.getLogger(__name__)` instead of calling the root logger
  directly.
- **`UP025`** — `u''` prefixes removed.
- **`I001`** — import blocks reformatted to ruff's isort profile (one import
  per line, alphabetized).
- **`UP008`** — `super(ClassName, self)` replaced with bare `super()`.
- **`UP004`** — explicit `object` inheritance removed.
- Plus a long tail of rules ruff added between the 250-error count above and
  0.16.4 (`RUF012`, `BLE001`, `SIM*`, `S110`, `YTT204`, etc.), each fixed or
  given a targeted, justified `noqa` — see the modernization PR for details.

The one caution below was honoured:

- **`TRY004` was not auto-fixed.** `user_data.validate_hosts`,
  `validate_settings`, and a few sites in `settings.py` still raise
  `ValueError` (not `TypeError`) for a malformed payload, each with a
  `# noqa: TRY004` and a comment explaining why. `handler.py` catches
  `ValueError` at these call sites to return 400; raising `TypeError` would
  turn a bad request into an unhandled 500 and break tests. The current
  behaviour is unchanged.

The modernization was done in one pass across the whole repository, as
originally planned, so no module is left stylistically inconsistent with
the ones it mirrors.

Note that the plans and specs under `docs/superpowers/` that predate this
work mandate the old style as an explicit constraint; they now carry a
historical-note callout pointing here instead of being rewritten.

## Cosmetic

- The administrator and user host tables have different column counts, so their
  columns do not line up vertically. Fixing it needs template restructuring.
- `get_user_data_dir` lets an `OSError` from `realpath` escape as `OSError`
  rather than the documented `ValueError`. Inherited from `user_keys.py`.
- `apply_config_settings` cannot distinguish a config-supplied `false` from the
  default `false`. Pre-existing pattern; harmless for the current keys.
- The "enabled but unconfigured" warning arguably belongs in
  `settings.check_user_data_dir`, which already owns the empty-directory
  decision; it is now checked in two places.
