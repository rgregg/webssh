# JavaScript Test Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the user-hosts client code a dependency-free unit test suite that runs in CI on every pull request.

**Architecture:** Decision logic moves out of `webssh/static/js/main.js` into a new pure module `webssh/static/js/user-hosts.js`; DOM reading stays in `main.js`, which reads the pane into plain values and passes them to the module. Because the extracted surface is pure, the tests need no jsdom, no jQuery, and no npm packages — Node's built-in `node --test` is the entire harness.

**Tech Stack:** ES5 JavaScript, Node 20+ `node:test` and `node:assert`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-07-31-js-test-coverage-design.md`

## Global Constraints

- **Zero dependencies.** `package.json` declares no `dependencies` and no `devDependencies`. Nothing is installed in CI; there is no lockfile. If you find yourself wanting a package, stop and report instead.
- **ES5 only in `webssh/static/js/`.** `var` only, no arrow functions, no `const`/`let`, no template literals, no `Object.assign`. The module ships to browsers alongside the existing ES5 `main.js`. Test files under `tests/js/` also stay ES5 for consistency, though Node would accept more.
- **The extraction must be behaviour-preserving.** Every moved function keeps its current semantics exactly, including edge cases that look like bugs. This is a refactor plus tests, not a redesign. If you believe a moved function is wrong, report it — do not fix it here.
- **`host_key` / `host_keys` asymmetry is deliberate and long-standing.** Input and submitted payloads use `host_key` (singular; string or list). Stored and returned records use `host_keys` (plural, always a list). Getting this backwards silently drops users' pinned host keys.
- **Secrets never leave the client.** No function in the new module may ever emit `credential`, `totp`, `password`, `passphrase`, or `privatekey`. Task 6 enforces this as a property over every builder.
- **The Python suite must stay green at 234 passed.** Run `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q` (the venv lives at the ORIGINAL repo path, not the worktree).

**Baseline:** `node --test tests/js/` does not exist yet. `pytest` is green at 234. Verify the Python baseline before starting.

**A note on why this exists.** Review of the client-side tasks found one Critical and eight Important defects, versus roughly one per server-side task. Every test in this plan traces to a defect that review or browser testing actually found; the table in each task names it. Do not add tests that guard nothing — they cost maintenance and buy no signal.

---

### Task 1: Harness, module skeleton, and `validate_port`

The scaffold rides along with the first real extraction so that the toolchain is proven end to end by a test that matters, rather than by a placeholder.

**Files:**
- Create: `package.json`, `webssh/static/js/user-hosts.js`, `tests/js/user-hosts.test.js`
- Modify: `webssh/templates/index.html:176-191` (script tags), `.github/workflows/python.yml`
- Modify: `webssh/static/js/main.js:879-917` (`collect_host_rows` port branch)

**Interfaces:**
- Consumes: nothing.
- Produces: global `webssh_hosts` (also `module.exports` under Node) with `validate_port(text)` returning one of exactly three shapes:
  - `{omit: true}` — the field was blank; the caller must omit `port` entirely so the server applies its documented default of 22
  - `{port: <int>}` — valid, 1–65535
  - `{invalid: true}` — present but not an integer in range. The caller composes the user-facing message, because it needs the host name.

- [ ] **Step 1: Write the failing test**

Create `tests/js/user-hosts.test.js`:

```js
'use strict';

var test = require('node:test');
var assert = require('node:assert');
var hosts = require('../../webssh/static/js/user-hosts.js');

test('validate_port omits a blank port so the server default applies', function () {
  assert.deepStrictEqual(hosts.validate_port(''), {omit: true});
  assert.deepStrictEqual(hosts.validate_port('   '), {omit: true});
});

test('validate_port accepts values in range', function () {
  assert.deepStrictEqual(hosts.validate_port('22'), {port: 22});
  assert.deepStrictEqual(hosts.validate_port('2222'), {port: 2222});
  assert.deepStrictEqual(hosts.validate_port('65535'), {port: 65535});
  assert.deepStrictEqual(hosts.validate_port('1'), {port: 1});
});

test('validate_port rejects out-of-range values instead of rewriting them', function () {
  // Regression: a typo was once silently clamped to 22, routing around the
  // server-side 1-65535 check and connecting the user to a port they did
  // not type.
  assert.deepStrictEqual(hosts.validate_port('0'), {invalid: true});
  assert.deepStrictEqual(hosts.validate_port('-5'), {invalid: true});
  assert.deepStrictEqual(hosts.validate_port('99999'), {invalid: true});
  assert.deepStrictEqual(hosts.validate_port('65536'), {invalid: true});
});

test('validate_port rejects non-numeric text', function () {
  assert.deepStrictEqual(hosts.validate_port('abc'), {invalid: true});
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test tests/js/`
Expected: FAIL — `Cannot find module '../../webssh/static/js/user-hosts.js'`

- [ ] **Step 3: Create the module**

Create `webssh/static/js/user-hosts.js`:

```js
/*jslint browser:true */
/*
 * Pure decision logic for the user-managed hosts and settings feature.
 *
 * This module holds no DOM access and no jQuery dependency: main.js reads
 * the settings pane into plain values and passes them here. That keeps this
 * file unit-testable under `node --test` with no browser and no packages.
 */

var webssh_hosts = (function () {
  'use strict';

  // Returns exactly one of {omit: true}, {port: n}, or {invalid: true}.
  // A blank port is omitted rather than defaulted here, so the server
  // applies its own documented default; a typed value is never rewritten.
  function validate_port(text) {
    var trimmed = (text === undefined || text === null) ? '' : String(text).trim();
    if (!trimmed) {
      return {omit: true};
    }
    var port = parseInt(trimmed, 10);
    if (!(port > 0 && port <= 65535)) {
      return {invalid: true};
    }
    return {port: port};
  }

  return {
    validate_port: validate_port
  };
}());

if (typeof module !== 'undefined' && module.exports) {
  module.exports = webssh_hosts;
}
```

Note `parseInt('22abc', 10)` is `22`, matching the current behaviour in `main.js:906`. Preserve that; do not tighten it.

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test tests/js/`
Expected: PASS, 4 tests.

- [ ] **Step 5: Add package.json**

Create `package.json`:

```json
{
  "name": "webssh-client-tests",
  "private": true,
  "description": "Unit tests for the WebSSH browser client. No runtime dependencies.",
  "engines": {
    "node": ">=20"
  },
  "scripts": {
    "test": "node --test tests/js/"
  }
}
```

Run: `npm test`
Expected: PASS, same 4 tests. There is nothing to install first — that is the point.

- [ ] **Step 6: Load the module in the browser**

In `webssh/templates/index.html`, add the new script immediately before `main.js` (currently line 191), so the global exists when `main.js` runs:

```html
    <script src="static/js/user-hosts.js"></script>
    <script src="static/js/main.js"></script>
```

- [ ] **Step 7: Use `validate_port` from main.js**

In `main.js`, replace the port branch of `collect_host_rows` (lines 902-913) with a call into the module. The surrounding function is otherwise unchanged in this task:

```js
      // Leave port unset when blank so the server applies its documented
      // default; never rewrite a value the user actually typed.
      var port_text = row.find('.host-port').val().trim();
      var port_result = webssh_hosts.validate_port(port_text);
      if (port_result.invalid) {
        row.find('.host-port').addClass('input-error');
        error = 'Invalid port "' + port_text + '" for host "' + name + '" (must be 1-65535).';
        return;
      }
      if (port_result.port) {
        host.port = port_result.port;
      }
```

- [ ] **Step 8: Add the CI job**

In `.github/workflows/python.yml`, add a `js` job alongside `lint` and `test`:

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

Then add `js` to the `docker` job's `needs:` list so a JavaScript failure blocks the release exactly as a Python failure does. It currently reads `needs: [lint, test]`; make it `needs: [lint, test, js]`.

- [ ] **Step 9: Verify nothing regressed**

Run: `node --test tests/js/`
Expected: PASS, 4 tests.

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS, 234 passed. The template change touches a rendered page, so a Python failure here means the script tag broke something.

- [ ] **Step 10: Commit**

```bash
git add package.json webssh/static/js/user-hosts.js tests/js/user-hosts.test.js \
        webssh/templates/index.html webssh/static/js/main.js .github/workflows/python.yml
git commit -m "test: add dependency-free JS harness and cover port validation"
```

---

### Task 2: `build_host_payload`

**Files:**
- Modify: `webssh/static/js/user-hosts.js`, `tests/js/user-hosts.test.js`
- Modify: `webssh/static/js/main.js:879-917` (`collect_host_rows`)

**Interfaces:**
- Consumes: `validate_port` from Task 1.
- Produces: `build_host_payload(rows)` where `rows` is an array of plain objects
  `{name, hostname, port_text, keys_text, username, default_command}` (all strings,
  untrimmed as read from the DOM). Returns
  `{hosts: [...], error: null|string, error_index: -1|<int>}`.
  `error_index` is new: `main.js` needs it to mark the offending row, which the
  old inline version did directly. Submitted hosts use `host_key` (singular).

- [ ] **Step 1: Write the failing tests**

Append to `tests/js/user-hosts.test.js`:

```js
function row(over) {
  var base = {name: '', hostname: '', port_text: '', keys_text: '',
              username: '', default_command: ''};
  for (var k in over) { base[k] = over[k]; }
  return base;
}

test('build_host_payload maps a full row and trims every field', function () {
  var out = hosts.build_host_payload([row({
    name: '  homelab ', hostname: ' nas.lan ', port_text: '2222',
    keys_text: ' ssh-ed25519 AAAA ', username: ' ryan ',
    default_command: ' tmux attach '
  })]);
  assert.strictEqual(out.error, null);
  assert.deepStrictEqual(out.hosts, [{
    name: 'homelab', hostname: 'nas.lan', host_key: ['ssh-ed25519 AAAA'],
    username: 'ryan', default_command: 'tmux attach', port: 2222
  }]);
});

test('build_host_payload emits host_key singular, never host_keys', function () {
  // The server consumes host_key and returns host_keys. Sending the wrong
  // one silently drops the user's pinned keys, which downgrades the host to
  // the global policy.
  var out = hosts.build_host_payload([row({
    hostname: 'a.com', keys_text: 'ssh-ed25519 AAAA'
  })]);
  assert.ok('host_key' in out.hosts[0]);
  assert.ok(!('host_keys' in out.hosts[0]));
});

test('build_host_payload splits multiple keys and drops blank lines', function () {
  var out = hosts.build_host_payload([row({
    hostname: 'a.com', keys_text: 'ssh-ed25519 AAA\n\n  \nssh-rsa BBB\n'
  })]);
  assert.deepStrictEqual(out.hosts[0].host_key, ['ssh-ed25519 AAA', 'ssh-rsa BBB']);
});

test('build_host_payload defaults an empty name to the hostname', function () {
  var out = hosts.build_host_payload([row({hostname: 'nas.lan'})]);
  assert.strictEqual(out.hosts[0].name, 'nas.lan');
});

test('build_host_payload omits port entirely when blank', function () {
  var out = hosts.build_host_payload([row({hostname: 'a.com'})]);
  assert.ok(!('port' in out.hosts[0]),
            'a blank port must be absent, not null/0/NaN, so the server defaults it');
});

test('build_host_payload skips rows with a blank hostname', function () {
  var out = hosts.build_host_payload([
    row({hostname: 'a.com'}),
    row({name: 'half-filled', keys_text: 'ssh-ed25519 AAA'}),
    row({hostname: 'b.com'})
  ]);
  assert.strictEqual(out.hosts.length, 2);
  assert.deepStrictEqual([out.hosts[0].hostname, out.hosts[1].hostname],
                         ['a.com', 'b.com']);
});

test('build_host_payload reports an invalid port with the offending row index', function () {
  var out = hosts.build_host_payload([
    row({hostname: 'a.com'}),
    row({name: 'db', hostname: 'b.com', port_text: '99999'})
  ]);
  assert.strictEqual(out.error,
    'Invalid port "99999" for host "db" (must be 1-65535).');
  assert.strictEqual(out.error_index, 1);
});

test('build_host_payload stops at the first invalid row', function () {
  var out = hosts.build_host_payload([
    row({hostname: 'a.com', port_text: '0'}),
    row({hostname: 'b.com', port_text: '70000'})
  ]);
  assert.strictEqual(out.error_index, 0);
});

test('build_host_payload returns an empty list for no rows', function () {
  // An explicit empty list is a legitimate "clear my hosts", distinct from
  // a failure, and the server honours it as such.
  assert.deepStrictEqual(hosts.build_host_payload([]),
                         {hosts: [], error: null, error_index: -1});
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test tests/js/`
Expected: FAIL — `hosts.build_host_payload is not a function`

- [ ] **Step 3: Implement it**

Add to `user-hosts.js` above the `return` block, and add `build_host_payload` to the returned object:

```js
  function split_keys(text) {
    var raw = (text === undefined || text === null) ? '' : String(text);
    var parts = raw.split('\n');
    var cleaned = [];
    for (var i = 0; i < parts.length; i++) {
      var k = parts[i].trim();
      if (k) {
        cleaned.push(k);
      }
    }
    return cleaned;
  }

  function trimmed(value) {
    return (value === undefined || value === null) ? '' : String(value).trim();
  }

  // rows: [{name, hostname, port_text, keys_text, username, default_command}]
  // Rows with a blank hostname are skipped, matching the pane's behaviour of
  // ignoring a half-filled row rather than submitting it.
  function build_host_payload(rows) {
    var result = [];
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var hostname = trimmed(r.hostname);
      if (!hostname) {
        continue;
      }
      var name = trimmed(r.name) || hostname;
      var host = {
        name: name,
        hostname: hostname,
        host_key: split_keys(r.keys_text),
        username: trimmed(r.username),
        default_command: trimmed(r.default_command)
      };
      var port_result = validate_port(r.port_text);
      if (port_result.invalid) {
        return {
          hosts: [],
          error: 'Invalid port "' + trimmed(r.port_text) +
                 '" for host "' + name + '" (must be 1-65535).',
          error_index: i
        };
      }
      if (port_result.port) {
        host.port = port_result.port;
      }
      result.push(host);
    }
    return {hosts: result, error: null, error_index: -1};
  }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test tests/js/`
Expected: PASS, 13 tests.

- [ ] **Step 5: Rewrite collect_host_rows to use it**

Replace `collect_host_rows` in `main.js` entirely. It now does DOM reading only:

```js
  function collect_host_rows(pane) {
    var rows = [];
    var row_els = [];
    pane.find('#user-host-rows .host-port').removeClass('input-error');
    pane.find('#user-host-rows tr.user-host').each(function() {
      var row = $(this);
      row_els.push(row);
      rows.push({
        name: row.find('.host-name').val(),
        hostname: row.find('.host-hostname').val(),
        port_text: row.find('.host-port').val(),
        keys_text: row.find('.host-keys').val(),
        username: row.find('.host-username').val(),
        default_command: row.find('.host-command').val()
      });
    });

    var built = webssh_hosts.build_host_payload(rows);
    if (built.error && built.error_index >= 0) {
      row_els[built.error_index].find('.host-port').addClass('input-error');
    }
    return {hosts: built.hosts, error: built.error};
  }
```

The returned shape `{hosts, error}` is unchanged, so the caller needs no edit.

- [ ] **Step 6: Verify nothing regressed**

Run: `node --test tests/js/`
Expected: PASS, 13 tests.

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS, 234 passed.

- [ ] **Step 7: Commit**

```bash
git add webssh/static/js/user-hosts.js tests/js/user-hosts.test.js webssh/static/js/main.js
git commit -m "test: extract and cover host payload construction"
```

---

### Task 3: `merge_settings` and `roaming_update`

**Files:**
- Modify: `webssh/static/js/user-hosts.js`, `tests/js/user-hosts.test.js`
- Modify: `webssh/static/js/main.js:920-945` (`collect_settings`), `:429-446` (`store_items`)

**Interfaces:**
- Consumes: the private `trimmed(value)` helper added to `user-hosts.js` in Task 2.
- Produces:
  - `ROAMING_FIELDS` — the exported map `{hostname: 'last_hostname', username: 'last_username', port: 'last_port'}`. `main.js` stops defining its own and uses this one, so there is a single source of truth.
  - `merge_settings(current, ui)` where `ui` is `{font_size_text, background, foreground, cursor, encoding, term, cursor_blink, key_source}`. Returns the settings object to PUT.
  - `roaming_update(name, value)` returning `{key: <stored key>, value: <string|int>}` or `null` when the field does not roam or the value is unusable.

**Naming note:** the spec calls this `roaming_from_form(names, values)`, taking the
whole field list. A per-field signature is used instead because the actual call
site in `store_items` already loops field by field and needs the localStorage
write interleaved; a batch signature would force that loop to run twice. The
behaviour is identical. Use `roaming_update`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/js/user-hosts.test.js`:

```js
function ui(over) {
  var base = {font_size_text: '', background: '', foreground: '', cursor: '',
              encoding: '', term: '', cursor_blink: true, key_source: 'upload'};
  for (var k in over) { base[k] = over[k]; }
  return base;
}

test('merge_settings carries roamed last-used values forward', function () {
  // Regression: the pane only knows appearance keys, and the settings PUT
  // replaces the whole blob, so every save used to wipe the roamed values.
  // That is invisible on one machine because localStorage covers it, and
  // only shows up on a second machine -- which is the point of roaming.
  var current = {last_hostname: 'nas.lan', last_username: 'ryan', last_port: 2222};
  var out = hosts.merge_settings(current, ui({font_size_text: '16'}));
  assert.strictEqual(out.last_hostname, 'nas.lan');
  assert.strictEqual(out.last_username, 'ryan');
  assert.strictEqual(out.last_port, 2222);
  assert.strictEqual(out.font_size, 16);
});

test('merge_settings omits roaming keys absent from current settings', function () {
  var out = hosts.merge_settings({}, ui({font_size_text: '16'}));
  assert.ok(!('last_hostname' in out),
            'absent keys must be omitted, not sent as null/undefined');
  assert.ok(!('last_port' in out));
});

test('merge_settings carries only the three known roaming keys', function () {
  var out = hosts.merge_settings(
    {last_hostname: 'a', nonsense: 'x', credential: 'secret'}, ui({}));
  assert.strictEqual(out.last_hostname, 'a');
  assert.ok(!('nonsense' in out));
  assert.ok(!('credential' in out));
});

test('merge_settings includes appearance values only when non-empty', function () {
  var out = hosts.merge_settings({}, ui({background: ' black ', foreground: ''}));
  assert.strictEqual(out.background, 'black');
  assert.ok(!('foreground' in out));
});

test('merge_settings omits a non-positive font size', function () {
  assert.ok(!('font_size' in hosts.merge_settings({}, ui({font_size_text: ''}))));
  assert.ok(!('font_size' in hosts.merge_settings({}, ui({font_size_text: '0'}))));
  assert.ok(!('font_size' in hosts.merge_settings({}, ui({font_size_text: 'abc'}))));
});

test('merge_settings always includes cursor_blink and key_source', function () {
  var out = hosts.merge_settings({}, ui({cursor_blink: false, key_source: 'stored'}));
  assert.strictEqual(out.cursor_blink, false);
  assert.strictEqual(out.key_source, 'stored');
});

test('roaming_update maps only the three roaming form fields', function () {
  assert.deepStrictEqual(hosts.roaming_update('hostname', 'nas.lan'),
                         {key: 'last_hostname', value: 'nas.lan'});
  assert.deepStrictEqual(hosts.roaming_update('username', 'ryan'),
                         {key: 'last_username', value: 'ryan'});
  assert.strictEqual(hosts.roaming_update('credential', 'hunter2'), null);
  assert.strictEqual(hosts.roaming_update('totp', '123456'), null);
  assert.strictEqual(hosts.roaming_update('passphrase', 'x'), null);
});

test('roaming_update coerces port to an integer', function () {
  // The server validates last_port as an int 1-65535; a string would be
  // rejected with a 400 the user never sees.
  assert.deepStrictEqual(hosts.roaming_update('port', '2222'),
                         {key: 'last_port', value: 2222});
  assert.strictEqual(typeof hosts.roaming_update('port', '2222').value, 'number');
});

test('roaming_update drops an unusable port instead of sending it', function () {
  assert.strictEqual(hosts.roaming_update('port', 'abc'), null);
  assert.strictEqual(hosts.roaming_update('port', '0'), null);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test tests/js/`
Expected: FAIL — `hosts.merge_settings is not a function`

- [ ] **Step 3: Implement them**

Add to `user-hosts.js`, and add `ROAMING_FIELDS`, `merge_settings`, and `roaming_update` to the returned object:

```js
  // Form field name -> stored settings key. These three are the ONLY fields
  // that roam. Everything else in the form, including credential and totp,
  // is deliberately absent so secrets cannot reach the server structurally.
  var ROAMING_FIELDS = {
    hostname: 'last_hostname',
    username: 'last_username',
    port: 'last_port'
  };

  var APPEARANCE_KEYS = ['background', 'foreground', 'cursor', 'encoding', 'term'];

  function merge_settings(current, ui) {
    var settings = {};
    var size = parseInt(ui.font_size_text, 10);
    if (size > 0) {
      settings.font_size = size;
    }
    for (var i = 0; i < APPEARANCE_KEYS.length; i++) {
      var key = APPEARANCE_KEYS[i];
      var value = trimmed(ui[key]);
      if (value) {
        settings[key] = value;
      }
    }
    settings.cursor_blink = ui.cursor_blink;
    settings.key_source = ui.key_source;
    // The settings PUT replaces the whole stored blob and this pane only
    // knows appearance keys, so carry the roamed values forward. Only the
    // known keys, to keep the secrets invariant structural.
    for (var name in ROAMING_FIELDS) {
      var roam_key = ROAMING_FIELDS[name];
      if (current[roam_key] !== undefined) {
        settings[roam_key] = current[roam_key];
      }
    }
    return settings;
  }

  function roaming_update(name, value) {
    var roam_key = ROAMING_FIELDS[name];
    if (!roam_key) {
      return null;
    }
    if (name === 'port') {
      var port = parseInt(value, 10);
      if (!(port > 0)) {
        return null;
      }
      return {key: roam_key, value: port};
    }
    return {key: roam_key, value: value};
  }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test tests/js/`
Expected: PASS, 22 tests.

- [ ] **Step 5: Use them from main.js**

Delete the `ROAMING_FIELDS` definition at `main.js:422-426` and replace every reference to it with `webssh_hosts.ROAMING_FIELDS`. Then rewrite the two call sites.

`collect_settings` becomes DOM reading plus one call:

```js
  function collect_settings(pane) {
    return webssh_hosts.merge_settings(user_settings, {
      font_size_text: pane.find('#set-font-size').val(),
      background: pane.find('#set-background').val(),
      foreground: pane.find('#set-foreground').val(),
      cursor: pane.find('#set-cursor').val(),
      encoding: pane.find('#set-encoding').val(),
      term: pane.find('#set-term').val(),
      cursor_blink: pane.find('#set-cursor-blink').is(':checked'),
      key_source: pane.find('#set-key-source').val()
    });
  }
```

The roaming branch of `store_items` becomes:

```js
      if (value) {
        window.localStorage.setItem(name, value);
        var roamed = webssh_hosts.roaming_update(name, value);
        if (roamed) {
          user_settings[roamed.key] = roamed.value;
        }
      }
```

- [ ] **Step 6: Verify nothing regressed**

Run: `node --test tests/js/`
Expected: PASS, 22 tests.

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS, 234 passed.

Then confirm by reading that no reference to a bare `ROAMING_FIELDS` survives in `main.js`:

Run: `grep -n 'ROAMING_FIELDS' webssh/static/js/main.js`
Expected: every hit is prefixed `webssh_hosts.`

- [ ] **Step 7: Commit**

```bash
git add webssh/static/js/user-hosts.js tests/js/user-hosts.test.js webssh/static/js/main.js
git commit -m "test: extract and cover settings merge and roaming fields"
```

---

### Task 4: `resolve_terminal_options` and `save_error_text`

**Files:**
- Modify: `webssh/static/js/user-hosts.js`, `tests/js/user-hosts.test.js`
- Modify: `webssh/static/js/main.js:1185-1199` (`termOptions`), `:1047-1055` (`save_error_text`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `resolve_terminal_options(url_opts, stored)` returning `{cursorBlink, theme: {background, foreground, cursor}}` plus `fontSize` only when a positive size resolves.
  - `save_error_text(status, body)` where `body` is the parsed JSON response or `null`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/js/user-hosts.test.js`:

```js
test('resolve_terminal_options lets a URL parameter beat a stored value', function () {
  // Existing shared links carry ?fontsize= and ?bgcolor=; a stored
  // preference must never override an explicit URL parameter.
  var out = hosts.resolve_terminal_options(
    {fontsize: '20', bgcolor: 'navy'},
    {font_size: 19, background: 'black'});
  assert.strictEqual(out.fontSize, 20);
  assert.strictEqual(out.theme.background, 'navy');
});

test('resolve_terminal_options falls back to stored values', function () {
  var out = hosts.resolve_terminal_options({}, {font_size: 19, background: 'black'});
  assert.strictEqual(out.fontSize, 19);
  assert.strictEqual(out.theme.background, 'black');
});

test('resolve_terminal_options falls back to built-in defaults', function () {
  var out = hosts.resolve_terminal_options({}, {});
  assert.strictEqual(out.theme.background, 'black');
  assert.strictEqual(out.theme.foreground, 'white');
  assert.strictEqual(out.theme.cursor, 'white');
  assert.strictEqual(out.cursorBlink, true);
});

test('resolve_terminal_options omits fontSize when nothing resolves', function () {
  assert.ok(!('fontSize' in hosts.resolve_terminal_options({}, {})));
});

test('resolve_terminal_options ignores a malformed font size', function () {
  // A bad stored value must not break the terminal.
  assert.ok(!('fontSize' in hosts.resolve_terminal_options({fontsize: 'abc'}, {})));
});

test('resolve_terminal_options honours cursor_blink false', function () {
  assert.strictEqual(
    hosts.resolve_terminal_options({}, {cursor_blink: false}).cursorBlink, false);
});

test('resolve_terminal_options falls back through fontcolor for the cursor', function () {
  var out = hosts.resolve_terminal_options({fontcolor: 'lime'}, {});
  assert.strictEqual(out.theme.cursor, 'lime');
});

test('save_error_text surfaces the server message on 400', function () {
  assert.strictEqual(
    hosts.save_error_text(400, {error: 'Invalid port "99999" for host "db".'}),
    'Invalid port "99999" for host "db".');
});

test('save_error_text falls back to a generic message on a bodyless 400', function () {
  assert.strictEqual(hosts.save_error_text(400, null),
                     'Rejected: check hostnames, ports, and host keys.');
});

test('save_error_text never surfaces server detail on 500', function () {
  // Server-state messages can embed filesystem paths. The server already
  // genericises them; the client must not undo that by echoing a body.
  assert.strictEqual(
    hosts.save_error_text(500, {error: '/var/lib/webssh/user-data denied'}),
    'Save failed.');
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test tests/js/`
Expected: FAIL — `hosts.resolve_terminal_options is not a function`

- [ ] **Step 3: Implement them**

Add to `user-hosts.js` and to the returned object:

```js
  // Precedence: URL parameter, then stored preference, then built-in default.
  function resolve_terminal_options(url_opts, stored) {
    var options = {
      cursorBlink: stored.cursor_blink !== false,
      theme: {
        background: url_opts.bgcolor || stored.background || 'black',
        foreground: url_opts.fontcolor || stored.foreground || 'white',
        cursor: url_opts.cursor || stored.cursor ||
                url_opts.fontcolor || stored.foreground || 'white'
      }
    };
    var fontsize = parseInt(url_opts.fontsize || stored.font_size, 10);
    if (fontsize && fontsize > 0) {
      options.fontSize = fontsize;
    }
    return options;
  }

  // A 400 describes the user's own input and is safe to show. Anything else
  // may describe server state, so it gets a fixed generic message.
  function save_error_text(status, body) {
    if (status === 400) {
      if (body && body.error) {
        return body.error;
      }
      return 'Rejected: check hostnames, ports, and host keys.';
    }
    return 'Save failed.';
  }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test tests/js/`
Expected: PASS, 32 tests.

- [ ] **Step 5: Use them from main.js**

Replace the `termOptions` construction and the `fontsize` block (lines 1185-1199) with:

```js
          termOptions = webssh_hosts.resolve_terminal_options(
            url_opts_data, user_settings);
```

Take care with the surrounding `var` declaration list: `termOptions` is currently the last declarator in a comma-separated chain, so keep the chain valid.

Replace `save_error_text` with a thin adapter that keeps the existing single-argument call sites working:

```js
  function save_error_text(xhr) {
    return webssh_hosts.save_error_text(
      xhr ? xhr.status : 0, xhr ? xhr.responseJSON : null);
  }
```

- [ ] **Step 6: Verify nothing regressed**

Run: `node --test tests/js/`
Expected: PASS, 32 tests.

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS, 234 passed.

Run: `node --check webssh/static/js/main.js`
Expected: no output. This catches a broken `var` chain from Step 5.

- [ ] **Step 7: Commit**

```bash
git add webssh/static/js/user-hosts.js tests/js/user-hosts.test.js webssh/static/js/main.js
git commit -m "test: extract and cover terminal option precedence and error text"
```

---

### Task 5: Migration helpers

The migration rewrites the user's entire host list, so a dropped field destroys pinned keys. It is the highest-consequence pure logic in the client.

**Files:**
- Modify: `webssh/static/js/user-hosts.js`, `tests/js/user-hosts.test.js`
- Modify: `webssh/static/js/main.js:553-600` (`migrate_local_commands`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `parse_command_key(key)` returning `{hostname, port}` or `null` for a key that is not a legacy command key.
  - `merge_migrated_commands(stored_hosts, found)` where `stored_hosts` is the list from `GET /api/hosts` (records carrying `host_keys` plural) and `found` is `[{hostname, port, command}]`. Returns `{payload, changed}`; `payload` uses `host_key` singular and is `[]` when `changed` is false.

- [ ] **Step 1: Write the failing tests**

Append to `tests/js/user-hosts.test.js`:

```js
test('parse_command_key reads a legacy command key', function () {
  assert.deepStrictEqual(hosts.parse_command_key('command:nas.lan:2222'),
                         {hostname: 'nas.lan', port: 2222});
});

test('parse_command_key defaults a missing port to 22', function () {
  assert.deepStrictEqual(hosts.parse_command_key('command:nas.lan:'),
                         {hostname: 'nas.lan', port: 22});
});

test('parse_command_key ignores unrelated localStorage keys', function () {
  assert.strictEqual(hosts.parse_command_key('hostname'), null);
  assert.strictEqual(hosts.parse_command_key('webssh_migrated_commands'), null);
  assert.strictEqual(hosts.parse_command_key(''), null);
  assert.strictEqual(hosts.parse_command_key(null), null);
});

test('merge_migrated_commands preserves every field of every host', function () {
  // This payload replaces the user's whole host list. A dropped field here
  // silently destroys pinned host keys.
  var stored = [{
    name: 'homelab', hostname: 'nas.lan', port: 2222,
    host_keys: ['ssh-ed25519 AAA'], username: 'ryan', default_command: ''
  }];
  var out = hosts.merge_migrated_commands(
    stored, [{hostname: 'nas.lan', port: 2222, command: 'tmux attach'}]);
  assert.strictEqual(out.changed, true);
  assert.deepStrictEqual(out.payload, [{
    name: 'homelab', hostname: 'nas.lan', port: 2222,
    host_key: ['ssh-ed25519 AAA'], username: 'ryan',
    default_command: 'tmux attach'
  }]);
});

test('merge_migrated_commands converts host_keys to host_key', function () {
  var out = hosts.merge_migrated_commands(
    [{name: 'a', hostname: 'a.com', port: 22, host_keys: ['ssh-rsa AAA'],
      username: '', default_command: ''}],
    [{hostname: 'a.com', port: 22, command: 'htop'}]);
  assert.deepStrictEqual(out.payload[0].host_key, ['ssh-rsa AAA']);
  assert.ok(!('host_keys' in out.payload[0]));
});

test('merge_migrated_commands carries through hosts it does not migrate', function () {
  var stored = [
    {name: 'a', hostname: 'a.com', port: 22, host_keys: [], username: '',
     default_command: ''},
    {name: 'b', hostname: 'b.com', port: 22, host_keys: ['ssh-rsa BBB'],
     username: 'bob', default_command: 'top'}
  ];
  var out = hosts.merge_migrated_commands(
    stored, [{hostname: 'a.com', port: 22, command: 'htop'}]);
  assert.strictEqual(out.payload.length, 2);
  assert.deepStrictEqual(out.payload[1], {
    name: 'b', hostname: 'b.com', port: 22, host_key: ['ssh-rsa BBB'],
    username: 'bob', default_command: 'top'
  });
});

test('merge_migrated_commands never invents a host', function () {
  var out = hosts.merge_migrated_commands(
    [], [{hostname: 'ghost.lan', port: 22, command: 'htop'}]);
  assert.strictEqual(out.changed, false);
  assert.deepStrictEqual(out.payload, []);
});

test('merge_migrated_commands does not overwrite an existing command', function () {
  var out = hosts.merge_migrated_commands(
    [{name: 'a', hostname: 'a.com', port: 22, host_keys: [], username: '',
      default_command: 'already set'}],
    [{hostname: 'a.com', port: 22, command: 'from localStorage'}]);
  assert.strictEqual(out.changed, false);
});

test('merge_migrated_commands reports no change when nothing matches', function () {
  var out = hosts.merge_migrated_commands(
    [{name: 'a', hostname: 'a.com', port: 22, host_keys: [], username: '',
      default_command: ''}],
    [{hostname: 'other.lan', port: 22, command: 'htop'}]);
  assert.strictEqual(out.changed, false);
  assert.deepStrictEqual(out.payload, []);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test tests/js/`
Expected: FAIL — `hosts.parse_command_key is not a function`

- [ ] **Step 3: Implement them**

Add to `user-hosts.js` and to the returned object:

```js
  // Legacy per-host default commands were stored under 'command:<host>:<port>'.
  function parse_command_key(key) {
    if (!key || String(key).indexOf('command:') !== 0) {
      return null;
    }
    var parts = String(key).split(':');
    return {
      hostname: parts[1],
      port: parseInt(parts[2], 10) || 22
    };
  }

  // Returns the full replacement payload, since PUT /api/hosts replaces the
  // whole list. Every stored field is carried through; only default_command
  // is filled in, and only where the host has none.
  function merge_migrated_commands(stored_hosts, found) {
    var index = {};
    var i;
    for (i = 0; i < stored_hosts.length; i++) {
      index[stored_hosts[i].hostname + ':' + stored_hosts[i].port] = stored_hosts[i];
    }
    var changed = false;
    for (i = 0; i < found.length; i++) {
      var match = index[found[i].hostname + ':' + found[i].port];
      if (match && !match.default_command) {
        match.default_command = found[i].command;
        changed = true;
      }
    }
    if (!changed) {
      return {payload: [], changed: false};
    }
    var payload = [];
    for (i = 0; i < stored_hosts.length; i++) {
      var h = stored_hosts[i];
      payload.push({
        name: h.name,
        hostname: h.hostname,
        port: h.port,
        host_key: h.host_keys || [],
        username: h.username || '',
        default_command: h.default_command || ''
      });
    }
    return {payload: payload, changed: true};
  }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test tests/js/`
Expected: PASS, 41 tests.

- [ ] **Step 5: Use them from main.js**

In `migrate_local_commands`, replace the key-scanning loop with `parse_command_key`:

```js
    var found = [];
    for (var i = 0; i < window.localStorage.length; i++) {
      var key = window.localStorage.key(i);
      var parsed = webssh_hosts.parse_command_key(key);
      if (parsed) {
        found.push({
          hostname: parsed.hostname,
          port: parsed.port,
          command: window.localStorage.getItem(key)
        });
      }
    }
```

and replace the index/merge/payload block inside the `$.get('/api/hosts').done(...)` callback with:

```js
      var merged = webssh_hosts.merge_migrated_commands(data.user_hosts || [], found);
      if (!merged.changed) {
        window.localStorage.setItem('webssh_migrated_commands', '1');
        return;
      }
      var payload = merged.payload;
```

Leave every guard around this untouched: the `running` flag, the `.always`, the flag-setting, and the rule that the PUT is issued only inside the GET's `.done`. Those are what make the migration data-loss-safe.

- [ ] **Step 6: Verify nothing regressed**

Run: `node --test tests/js/`
Expected: PASS, 41 tests.

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS, 234 passed.

Run: `node --check webssh/static/js/main.js`
Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add webssh/static/js/user-hosts.js tests/js/user-hosts.test.js webssh/static/js/main.js
git commit -m "test: extract and cover legacy command migration"
```

---

### Task 6: Secrets property test and developer documentation

**Files:**
- Modify: `tests/js/user-hosts.test.js`, `README.md`

**Interfaces:**
- Consumes: every builder from Tasks 1-5.
- Produces: nothing other tasks rely on.

- [ ] **Step 1: Write the property test**

Append to `tests/js/user-hosts.test.js`. It is written as a property over all builder outputs so a field added later is covered without a new test:

```js
var SECRETS = ['credential', 'totp', 'password', 'passphrase', 'privatekey'];

function assert_no_secrets(label, value) {
  var text = JSON.stringify(value);
  for (var i = 0; i < SECRETS.length; i++) {
    assert.ok(text.indexOf(SECRETS[i]) === -1,
              label + ' must never carry ' + SECRETS[i] + ', got: ' + text);
  }
}

test('no builder output can carry a secret field', function () {
  // The server whitelists keys as a backstop, but a client-side leak would
  // still transmit the secret over the wire and log it on a validation error.
  var poisoned = {
    name: 'a', hostname: 'a.com', port_text: '22', keys_text: '',
    username: 'u', default_command: 'cmd',
    credential: 'hunter2', totp: '123456', password: 'p',
    passphrase: 'pp', privatekey: 'pk'
  };
  assert_no_secrets('build_host_payload',
                    hosts.build_host_payload([poisoned]).hosts);

  var poisoned_current = {
    last_hostname: 'nas.lan', credential: 'hunter2', totp: '123456',
    password: 'p', passphrase: 'pp', privatekey: 'pk'
  };
  var poisoned_ui = {
    font_size_text: '14', background: '', foreground: '', cursor: '',
    encoding: '', term: '', cursor_blink: true, key_source: 'upload',
    credential: 'hunter2', totp: '123456'
  };
  assert_no_secrets('merge_settings',
                    hosts.merge_settings(poisoned_current, poisoned_ui));

  assert_no_secrets('merge_migrated_commands', hosts.merge_migrated_commands(
    [{name: 'a', hostname: 'a.com', port: 22, host_keys: [], username: '',
      default_command: '', credential: 'hunter2', totp: '123456'}],
    [{hostname: 'a.com', port: 22, command: 'htop'}]).payload);
});

test('roaming_update refuses every secret-bearing form field', function () {
  for (var i = 0; i < SECRETS.length; i++) {
    assert.strictEqual(hosts.roaming_update(SECRETS[i], 'leaked'), null,
                       SECRETS[i] + ' must not roam');
  }
});
```

- [ ] **Step 2: Run the tests**

Run: `node --test tests/js/`
Expected: PASS, 43 tests. These should pass without any implementation change — the builders construct fresh objects with known keys rather than copying their input, which is exactly the property being pinned. If either test FAILS, stop and report: a builder is copying its input wholesale, which is a real defect rather than a test to adjust.

- [ ] **Step 3: Document how to run the suite**

`README.md` has a `### Development` section ending with a "Run tests:" block that
covers Python only. Extend that block — do not create a new section:

````markdown
Run tests:

```bash
pip install pytest
python -m pytest tests
```

Browser client tests require Node 20+ and install nothing:

```bash
node --test tests/js/
```

They cover the pure decision logic in `webssh/static/js/user-hosts.js` — host
payload construction, port validation, settings merging, preference precedence,
and the legacy command migration. DOM behaviour in `main.js` (tab lifecycle, the
hostname input/select upgrade, asynchronous save sequencing) is not covered.
````

- [ ] **Step 4: Final verification**

Run: `node --test tests/js/`
Expected: PASS, 43 tests.

Run: `npm test`
Expected: PASS, 43 tests.

Run: `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
Expected: PASS, 234 passed.

Run: `node --check webssh/static/js/user-hosts.js && node --check webssh/static/js/main.js`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add tests/js/user-hosts.test.js README.md
git commit -m "test: pin the no-secrets invariant and document the JS suite"
```

---

## Verification Checklist

Before considering this complete:

- [ ] `node --test tests/js/` passes with 43 tests
- [ ] `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q` passes with 234
- [ ] `package.json` has no `dependencies` and no `devDependencies`
- [ ] No file under `webssh/static/js/` uses `const`, `let`, arrow functions, or template literals
- [ ] `webssh/static/js/user-hosts.js` contains no DOM access and no jQuery reference
- [ ] `user-hosts.js` is loaded before `main.js` in `index.html`
- [ ] The `docker` CI job lists `js` in its `needs:`
- [ ] The extraction is behaviour-preserving: every moved function does exactly what it did before
