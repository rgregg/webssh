# User-Editable Hosts — Deferred Follow-Ups

Findings raised during review of the user-editable-hosts branch that were
deliberately deferred rather than fixed before merge. None blocks merge. They are
recorded here so the judgement is available later; delete this file once it has
been triaged.

**Audited against the code on 2026-08-20.** Everything below still applies
except the struck-through items. The file-transfer work (PRs #30-#33) resolved
the JavaScript harness gap and, separately, fixed two test-isolation defects of
exactly the kind the Tests section describes.

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
  `main.js`. Now slightly higher stakes: `transfer-ui.js` reuses this helper via
  `wssh.get_xsrf_token`, so uploads and download tickets depend on it too.
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
- ~~**No JavaScript test harness exists in this repository.**~~ Fixed, and it
  was indeed the largest durable improvement: `tests/js/` now runs 67
  dependency-free `node --test` cases across `user-hosts.js` and
  `file-transfer.js`, with a CI job on Node 20, 22, and 24. `scripts/check_es5.js`
  additionally enforces the ES5 constraint that was previously upheld by review
  alone.

## Lint modernisation backlog

CI's `lint` job installed `ruff` unpinned, so the 0.16 release turned the gate
red across the whole repository without any code change — 250 errors on `main`,
308 on the user-hosts branch. The job is now pinned to `ruff==0.15.6`, the last
version under which the repository is clean. Upgrading the pin is worth doing,
but it is a deliberate piece of work rather than a version bump:

- **`UP032`** (88) — `.format()` calls that ruff wants as f-strings.
- **`LOG015`** (63) — `logging.info()` and friends on the root logger. The whole
  codebase does this; there are 61 such calls in `webssh/` alone.
- **`UP025`** (27) — `u''` prefixes.
- **`I001`** (25) — import blocks in the repository's compact parenthesised
  style rather than ruff's one-per-line isort profile.
- **`UP008`** (14) — `super(ClassName, self)` rather than bare `super()`.
- **`UP004`** (9) — explicit `object` inheritance.

Two cautions for whoever does it:

- **`TRY004` must not be auto-fixed.** It wants `TypeError` where
  `user_data.validate_hosts` and `validate_settings` raise `ValueError` for a
  malformed payload. `handler.py` catches `ValueError` at five sites to return
  400; raising `TypeError` would turn a bad request into an unhandled 500 and
  break twelve tests. The current behaviour is correct.
- Fix the whole repository in one pass or not at all. Modernising individual
  files leaves them stylistically inconsistent with the modules they mirror —
  `user_data.py` was written to match `user_keys.py`, and `test_user_data.py` to
  match `test_user_keys.py`, down to the import formatting.

Note that the plans and specs under `docs/superpowers/` mandate the current
style as an explicit constraint. If the codebase modernises, that guidance
becomes stale and should be updated or marked historical.

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
