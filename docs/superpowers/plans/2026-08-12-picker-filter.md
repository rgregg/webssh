# Download Picker Filter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Typing in the download picker's path box narrows the listing to matching files; changing the directory part re-lists that directory.

**Architecture:** Two pure functions (`split_path`, `match_entry`) go in the DOM-free, unit-tested `file-transfer.js`. All state — cached entries, the debounce timer, the stale-response guard — lives in `transfer-ui.js`, which already owns the picker's DOM.

**Tech Stack:** Browser JavaScript, ES5 only, tested with `node --test` and no npm packages.

**Spec:** `docs/superpowers/specs/2026-08-12-picker-filter-design.md`

## Global Constraints

- **ES5 only** under `webssh/static/js/`: no `const`, `let`, arrow functions, or template literals. CI enforces this via `scripts/check_es5.js`.
- **No new dependencies.** `package.json` must keep no `dependencies` and no `devDependencies`.
- `webssh/static/js/file-transfer.js` must stay free of DOM access and jQuery.
- Matching is **case-insensitive substring**; an empty filter matches everything.
- The re-list debounce is **250 ms**. Filtering is local with **no** debounce.
- Server listings cap at **1000 entries**; a filtered truncated listing must keep saying so.

**Baseline:** 313 Python tests and 59 JS tests pass at `25ea2fd` on branch `feature/file-transfer`.

**Verification commands:**
- JS tests: `node --test tests/js/*.test.js`
- Python (unaffected, must not regress): `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q`
- ES5 gate: `node scripts/check_es5.js`

---

## File Structure

| File | Responsibility | Change |
| --- | --- | --- |
| `webssh/static/js/file-transfer.js` | Pure logic, no DOM | Add `split_path`, `match_entry` |
| `tests/js/file-transfer.test.js` | `node --test` coverage | Add cases for both |
| `webssh/static/js/transfer-ui.js` | Picker DOM, state, requests | Rewrite `open_picker` internals |
| `docs/superpowers/specs/2026-08-10-file-transfer-design.md:159-161` | Prior design | Correct the superseded paragraph |
| `README.md` | User docs | Document filtering |

---

### Task 1: `split_path` and `match_entry`

**Files:**
- Modify: `webssh/static/js/file-transfer.js`
- Test: `tests/js/file-transfer.test.js`

**Interfaces:**
- Consumes: nothing.
- Produces: `split_path(input) -> {dir: string|null, filter: string}` and `match_entry(name, filter) -> boolean`, both exported on the `webssh_transfer` object.

`dir` is `null` when the input contains no `/` at all, meaning "keep whatever is currently listed". The caller owns that state, which is what keeps this function free of UI knowledge.

- [ ] **Step 1: Write the failing tests**

Append to `tests/js/file-transfer.test.js`:

```javascript
test('split_path splits at the last slash', function () {
  assert.deepStrictEqual(ft.split_path('/var/log/sys'),
    {dir: '/var/log', filter: 'sys'});
  assert.deepStrictEqual(ft.split_path('/var/log/'),
    {dir: '/var/log', filter: ''});
  assert.deepStrictEqual(ft.split_path('/a/b/c/file.txt'),
    {dir: '/a/b/c', filter: 'file.txt'});
});

test('split_path preserves root rather than yielding an empty directory', function () {
  // '/passwd' must list '/', not '' -- an empty path would be sent to the
  // server as a relative listing of the home directory.
  assert.deepStrictEqual(ft.split_path('/passwd'), {dir: '/', filter: 'passwd'});
  assert.deepStrictEqual(ft.split_path('/'), {dir: '/', filter: ''});
});

test('split_path reports no directory when the input has no slash', function () {
  // null means "keep the current listing" -- the caller owns that state.
  assert.deepStrictEqual(ft.split_path('syslog'), {dir: null, filter: 'syslog'});
  assert.deepStrictEqual(ft.split_path(''), {dir: null, filter: ''});
});

test('split_path tolerates null and undefined', function () {
  assert.deepStrictEqual(ft.split_path(null), {dir: null, filter: ''});
  assert.deepStrictEqual(ft.split_path(undefined), {dir: null, filter: ''});
});

test('match_entry matches a substring, not only a prefix', function () {
  assert.strictEqual(ft.match_entry('syslog', 'log'), true);
  assert.strictEqual(ft.match_entry('auth.log', 'log'), true);
  assert.strictEqual(ft.match_entry('logrotate.conf', 'log'), true);
});

test('match_entry ignores case in both directions', function () {
  assert.strictEqual(ft.match_entry('Logrotate.conf', 'log'), true);
  assert.strictEqual(ft.match_entry('syslog', 'LOG'), true);
});

test('match_entry with an empty filter matches everything', function () {
  assert.strictEqual(ft.match_entry('anything', ''), true);
  assert.strictEqual(ft.match_entry('anything', '   '), true);
  assert.strictEqual(ft.match_entry('anything', null), true);
});

test('match_entry rejects a non-match', function () {
  assert.strictEqual(ft.match_entry('syslog', 'zzz'), false);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test tests/js/file-transfer.test.js`
Expected: FAIL — `ft.split_path is not a function`

- [ ] **Step 3: Implement both functions**

In `webssh/static/js/file-transfer.js`, add before the `return {` block:

```javascript
  // Splits what the user typed into the directory to list and the fragment
  // to filter by. dir === null means "no directory was typed, keep whatever
  // is currently listed" -- the caller owns that state, so this stays free
  // of UI knowledge.
  function split_path(input) {
    var text = (input === undefined || input === null) ? '' : String(input);
    var cut = text.lastIndexOf('/');
    if (cut === -1) {
      return {dir: null, filter: text};
    }
    // Everything up to the last slash is the directory. For a path directly
    // under root that slice is empty, which would reach the server as a
    // relative listing of the home directory, so keep the slash.
    var dir = text.slice(0, cut);
    return {dir: dir === '' ? '/' : dir, filter: text.slice(cut + 1)};
  }

  function match_entry(name, filter) {
    var needle = (filter === undefined || filter === null)
      ? '' : String(filter).trim();
    if (!needle) {
      return true;
    }
    return String(name).toLowerCase().indexOf(needle.toLowerCase()) !== -1;
  }
```

Add both to the returned object:

```javascript
    split_path: split_path,
    match_entry: match_entry,
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test tests/js/file-transfer.test.js`
Expected: PASS — 19 tests in this file (11 existing + 8 new)

- [ ] **Step 5: Verify the constraints**

```bash
node scripts/check_es5.js
grep -n "document\.\|jQuery\|\$(" webssh/static/js/file-transfer.js
```
Expected: ES5 check passes; the grep produces no output (no DOM access).

- [ ] **Step 6: Commit**

```bash
git add webssh/static/js/file-transfer.js tests/js/file-transfer.test.js
git commit -m "feat: add path splitting and entry matching for the picker filter"
```

---

### Task 2: Wire filtering into the picker

**Files:**
- Modify: `webssh/static/js/transfer-ui.js` (the `open_picker` function)

**Interfaces:**
- Consumes: `webssh_transfer.split_path`, `webssh_transfer.match_entry`, `webssh_transfer.resolve_path`, `webssh_transfer.format_bytes`, `webssh_transfer.download_url`.
- Produces: no new exports; `open_picker(tab_id, worker_id)` keeps its signature.

This task has no automated tests — it is DOM wiring, consistent with the rest of the picker, and the repo has no browser harness. Verification is the manual list in Step 4.

- [ ] **Step 1: Replace `open_picker`**

Replace the whole `open_picker` function in `webssh/static/js/transfer-ui.js` with:

```javascript
  function open_picker(tab_id, worker_id) {
    var dialog = $('#transfer-picker');
    var list = dialog.find('.picker-list').empty();
    var input = dialog.find('.picker-path');

    // Everything the picker needs to remember for one open session.
    var state = {
      dir: null,          // directory currently listed
      entries: [],        // entries as returned by the server
      truncated: false,   // whether the server capped the listing
      seq: 0,             // request counter, for discarding stale responses
      timer: null         // pending re-list debounce
    };

    function note(text) {
      return $('<div class="picker-note"></div>').text(text);
    }

    function render(filter) {
      list.empty();
      var shown = 0;
      $.each(state.entries, function (i, entry) {
        if (!webssh_transfer.match_entry(entry.name, filter)) {
          return;
        }
        shown = shown + 1;
        var item = $('<div class="picker-item"></div>');
        item.toggleClass('is-dir', entry.is_dir);
        item.text(entry.name + (entry.is_dir ? '/' : ' \u2014 ' +
          webssh_transfer.format_bytes(entry.size)));
        item.on('click', function () {
          var path = webssh_transfer.resolve_path(state.dir, entry.name);
          // Clicking behaves exactly as typing the same text would, for
          // both kinds of row, so the list always reflects the box.
          input.val(entry.is_dir ? path + '/' : path);
          on_input();
        });
        list.append(item);
      });

      if (!shown) {
        list.append(note('No matching files'));
      }
      if (state.truncated) {
        // Filtering only searched what was fetched, so a missing file may
        // exist past the cap. Saying nothing would read as proof of absence.
        list.append(note(
          'Listing truncated at 1000 entries; the filter searched only those.'));
      }
    }

    function fetch_dir(dir, filter) {
      state.seq = state.seq + 1;
      var mine = state.seq;
      $.getJSON('/transfer/list', {id: worker_id, path: dir})
        .done(function (data) {
          if (mine !== state.seq) {
            return;   // a newer request has been issued; this one is stale
          }
          state.dir = data.path;
          state.entries = data.entries;
          state.truncated = !!data.truncated;
          // The filter may have moved on while this was in flight.
          render(webssh_transfer.split_path(input.val()).filter);
        })
        .fail(function (xhr) {
          if (mine !== state.seq) {
            return;
          }
          // Keep the previous entries on screen: one mistyped character
          // should not cost the user their place.
          list.append(note('Could not list directory (' + xhr.status + ')'));
        });
    }

    function on_input() {
      var parts = webssh_transfer.split_path(input.val());
      if (parts.dir === null || parts.dir === state.dir) {
        render(parts.filter);   // local, instant, no request
        return;
      }
      if (state.timer) {
        clearTimeout(state.timer);
      }
      state.timer = setTimeout(function () {
        state.timer = null;
        fetch_dir(parts.dir, parts.filter);
      }, 250);
    }

    var start = get_cwd(tab_id) || '.';
    input.val(start);
    fetch_dir(start, '');

    input.off('input.picker').on('input.picker', on_input);

    dialog.addClass('visible');
    dialog.find('.picker-download').off('click').on('click', function () {
      var path = input.val();
      if (path) {
        window.location = webssh_transfer.download_url(worker_id, path);
      }
      dialog.removeClass('visible');
    });
    dialog.find('.picker-cancel').off('click').on('click', function () {
      if (state.timer) {
        clearTimeout(state.timer);
      }
      dialog.removeClass('visible');
    });
  }
```

Three details that matter and are easy to lose:

- `input.off('input.picker')` before binding: `open_picker` runs every time the button is pressed, and without this the handlers stack, exactly like the `bind_drop` bug fixed in `0287713`.
- The stale guard compares against `state.seq`, not a boolean, so an out-of-order response from a slow directory cannot repaint over a newer one.
- On the failure path the previous entries stay; only a note is appended.

- [ ] **Step 2: Make the directory rows look clickable**

In `webssh/static/css/main.css`, the `.picker-item.is-dir` rules currently disable the hover affordance. Replace:

```css
.picker-item.is-dir { color: var(--text-muted); cursor: default; }

.picker-item.is-dir:hover { background: none; color: var(--text-muted); }
```

with:

```css
.picker-item.is-dir { color: var(--text-muted); }
```

so directories pick up the shared `.picker-item:hover` styling and read as clickable.

- [ ] **Step 3: Verify nothing regressed**

```bash
node --test tests/js/*.test.js
/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q
node scripts/check_es5.js
```
Expected: 67 JS tests pass, 313 Python tests pass, ES5 clean.

- [ ] **Step 4: Manual verification on the dev stack**

The dev stack runs the branch image. Rebuild it or copy the two changed files in, then check at `http://smart-home-services.lan:8083`:

- typing narrows the list with no visible lag
- completing a directory and typing `/` re-lists it
- clicking a directory row enters it; clicking a file row fills the path
- typing quickly through several directories leaves the last one displayed
- a directory with over 1000 entries keeps its truncation warning while filtered
- a nonexistent directory leaves the previous entries visible plus a status note
- pressing Download with a filter fragment still in the box fails with a 404 rather than downloading something unexpected

- [ ] **Step 5: Commit**

```bash
git add webssh/static/js/transfer-ui.js webssh/static/css/main.css
git commit -m "feat: filter the download picker as you type"
```

---

### Task 3: Correct the superseded documentation

**Files:**
- Modify: `docs/superpowers/specs/2026-08-10-file-transfer-design.md:159-161`
- Modify: `README.md` (the "File transfer" section)

Both currently state that directories are not selectable and that navigation is out of scope. The code now navigates, so leaving them is a documentation lie about a deliberate decision.

- [ ] **Step 1: Correct the file-transfer design doc**

In `docs/superpowers/specs/2026-08-10-file-transfer-design.md`, replace:

```
   Directories appear in the listing but are not selectable and cannot be
   clicked into — changing directory means editing the path box. Navigation is
   what separates this from the file browser that is out of scope.
```

with:

```
   Typing in the path box filters the listing, and changing the directory part
   re-lists it; directories are clickable. This supersedes the original
   no-navigation boundary — see
   `2026-08-12-picker-filter-design.md`. The picker still offers no tree, no
   rename, and no delete.
```

- [ ] **Step 2: Document it for users**

In `README.md`, in the "File transfer" section, after the paragraph beginning "Uploads land in the directory the shell is currently in", add:

```markdown
The download picker lists one directory at a time. Typing in its path box
filters the listing to names containing what you typed, and typing or
clicking a directory moves to it. Long listings are capped at 1000 entries,
and the picker says so when the cap applies.
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-08-10-file-transfer-design.md README.md
git commit -m "docs: describe picker filtering and retire the no-navigation note"
```

---

## Verification Checklist

- [ ] `node --test tests/js/*.test.js` passes with 67 tests
- [ ] `/home/ryan/github/rgregg/webssh/.venv/bin/python -m pytest -q` passes with 313
- [ ] `node scripts/check_es5.js` clean
- [ ] `package.json` still has no `dependencies` and no `devDependencies`
- [ ] `file-transfer.js` still contains no DOM access and no jQuery reference
- [ ] Re-opening the picker repeatedly does not stack `input` handlers
- [ ] A stale listing response cannot repaint over a newer one
- [ ] A truncated listing keeps its warning while filtered
