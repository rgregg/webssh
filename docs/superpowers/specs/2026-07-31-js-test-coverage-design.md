# JavaScript Test Coverage for the User-Hosts Client

**Date:** 2026-07-31
**Status:** Approved design, pending implementation

## Problem

The user-editable-hosts feature added roughly a thousand lines of client-side
JavaScript with no automated coverage. The repository has no JavaScript test
harness at all, so `webssh/static/js/main.js` is guarded only by code review and
by scripted browser passes run by hand.

That gap is not theoretical. Review of the client-side tasks found one Critical
and eight Important defects, against roughly one finding per server-side task,
and two further defects surfaced only when the application was driven in a real
browser. Several were silent-data-loss bugs: a save issued before the host list
loaded wiped every stored host, and every settings save erased the roamed
last-used values.

`main.js` is 2071 lines inside a single `jQuery(function ($) { ... })` closure
that exports nothing, so none of that logic is reachable from a test.

## Goal

A CI regression gate. The tests run in GitHub Actions on every pull request,
alongside the existing Python matrix, and a failure blocks the release job the
same way a pytest failure does.

## Approach

Decision logic moves out of `main.js` into a new module; DOM reading stays
behind. `main.js` reads the settings pane into plain values and passes them to
the module, which decides what to do with them.

This keeps the extracted surface genuinely pure, which in turn means the tests
need **no dependencies at all** — no jsdom, no jQuery, no npm packages. Node's
built-in `node --test` runner is the whole harness.

The alternative approaches were considered and rejected. Loading `main.js` into
jsdom avoids a refactor but requires stubbing xterm, WebSocket, and FormData
before the file will even load, and couples every test to DOM structure.
Committing the Playwright drivers gives the highest fidelity but needs a Chromium
download and a running Tornado server in CI, making it the slowest and flakiest
tier for a per-pull-request gate.

## The Module

`webssh/static/js/user-hosts.js`, using the ES5 global-with-CommonJS-guard
pattern so the browser gets a global and Node gets a `require`-able module:

```js
var webssh_hosts = (function () {
  // pure functions
  return { validate_port: validate_port, /* ... */ };
}());

if (typeof module !== 'undefined' && module.exports) {
  module.exports = webssh_hosts;
}
```

It loads from a `<script>` tag in `index.html` placed before `main.js`. It has no
dependency on jQuery and touches no globals other than its own.

Eight functions move, grouped below by the call site they come from:

| Function | Replaces logic now in |
| --- | --- |
| `validate_port(text)` → `{port}`, `{omit: true}`, or `{error}` | the port branch of `collect_host_rows` |
| `build_host_payload(rows)` → `{hosts}` or `{error}` | the row-to-payload mapping in `collect_host_rows` |
| `merge_settings(current, ui)` | the roaming carry-forward in `collect_settings` |
| `roaming_from_form(names, values)` | the `ROAMING_FIELDS` mapping in `store_items` |
| `resolve_terminal_options(url_opts, stored)` | the `termOptions` precedence chain |
| `parse_command_key(key)` and `merge_migrated_commands(hosts, found)` | `migrate_local_commands` |
| `save_error_text(status, body)` | `save_error_text`, already nearly pure |

The extraction must be behaviour-preserving. Each moved function keeps its
current semantics exactly; this is a refactor plus tests, not a redesign. The
Python suite and the browser behaviour verified during the feature's review must
be unchanged.

## Harness

`node --test tests/js/`, built into Node 20. A `package.json` exists only to
declare the test script and the Node version floor; it has no `dependencies` and
no `devDependencies`, so there is nothing to install and no lockfile to maintain
in a repository that is otherwise pure Python.

## Coverage

Every test traces to a defect that review or browser testing actually found.
Tests that do not guard a known failure mode are not worth their maintenance.

| Test | Defect it guards |
| --- | --- |
| Blank port omits the key; `99999`, `0`, `-5` return an error; `22` passes | A typo'd port was silently rewritten to 22, routing around server validation |
| Payload emits `host_key` singular; reads `host_keys` plural | A direction mismatch would silently drop pinned host keys |
| Rows with a blank hostname are skipped, not emitted as malformed | Half-filled rows reaching the server as invalid entries |
| `merge_settings` carries `last_hostname`, `last_username`, `last_port` forward | Every settings save wiped the roamed values, defeating roaming on a second machine |
| No builder output ever contains `credential`, `totp`, `password`, or `passphrase` | The security invariant that secrets never reach the server |
| URL parameter beats stored value beats built-in default | A stored preference silently overriding an explicit URL parameter |
| Migration preserves every field of every host and never fabricates one | The migration rewrites the whole host list; a dropped field destroys pinned keys |
| A 400 surfaces the server's message; a 500 does not | Server-state detail, including filesystem paths, leaking to clients |

The secrets test is written as a property over all builder outputs rather than a
single case, so a future field added to a payload is covered by default rather
than needing a new test.

## CI

A new job in `.github/workflows/python.yml`, parallel to `lint` and `test`:

```yaml
  js:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: node --test tests/js/
```

The `docker` job's `needs:` list gains `js`, so a JavaScript failure blocks the
release exactly as a Python failure does. Expected runtime is a few seconds:
there is no browser to download and nothing to install.

## Out of Scope

This design deliberately does not cover, and the resulting suite must not be
described as covering:

- The hostname field's input-to-select upgrade and its reverse.
- Tab lifecycle: opening, focusing, closing, and the last-tab fallback.
- The debounced settings flush and other asynchronous save sequencing.
- XSS safety of DOM construction.
- The guard preventing a save from clearing hosts before the list has loaded.
  This was the Critical defect found in review. Making it unit-testable would
  mean threading a `loaded` flag through `build_host_payload`, which was
  considered and rejected as not worth changing a shipped signature. The
  protection remains where it is today, in the Save button's disabled state,
  covered by code review and by browser verification.

These remain verified by review and by manual browser passes. A future
Playwright suite would close them; it is out of scope here because a
browser-dependent job is the wrong shape for a per-pull-request gate.

## Delivery

The work extends the existing `worktree-user-editable-hosts` branch and pull
request #29, so the feature and its tests land together.

This re-opens a diff that has already passed a full review pass, including a
security fix. The mitigation is that the extraction is behaviour-preserving and
mechanical, and the resulting diff gets its own review focused on that property:
for each moved function, does the moved code do exactly what the original did?
