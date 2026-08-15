# Download Picker: Filter As You Type — Design

Typing in the download picker's path box narrows the listing to matching
files, and moving to another directory re-lists it.

## Goal

The picker lists one directory. On a directory with many entries, finding the
file you want means scanning. Typing part of the name should narrow the list
immediately.

## Behaviour

The path box holds a full path. Its text is split at the **last** `/`:

| Typed | Directory | Filter |
| --- | --- | --- |
| `/var/log/` | `/var/log` | (none — everything shows) |
| `/var/log/sys` | `/var/log` | `sys` |
| `/etc/pass` | `/etc` | `pass` |
| `syslog` | (unchanged) | `syslog` |

- **Filtering happens on the server**, so it matches across the whole
  directory rather than only the entries that fit under the cap. The filter
  travels with the listing request, debounced by 250 ms.
- **The picker re-renders locally first** while that request is in flight,
  narrowing the entries it already holds, so typing still reacts
  immediately. The response then replaces them and is authoritative.
  The local pass narrows only when the user has *extended* the filter the
  held entries were fetched under; after a deletion the held set is missing
  entries, so it shows everything it has rather than hiding rows the server
  is about to restore.
- **Matching is case-insensitive substring.** `log` matches `syslog`,
  `auth.log`, and `Logrotate.conf`. An empty filter matches everything.
- **Directories are clickable**, appending `name/` to the box and re-listing.

### This supersedes an earlier decision

The file-transfer design states that directories are listed but not
selectable, because "navigation is what would turn this into a file browser."
Typing a path to change directories *is* navigation, so that boundary no
longer holds. Directories become clickable for consistency: leaving them inert
while the path box navigates would be arbitrary.

`docs/superpowers/specs/2026-08-10-file-transfer-design.md` and the README
both state the old behaviour and must be corrected. The picker still offers no
tree, no rename, and no delete — it remains a picker, not a file manager.

## Architecture

Two pure functions in `webssh/static/js/file-transfer.js`, which holds no DOM
access and is unit-tested under `node --test`:

```
split_path(input)  -> {dir: string, filter: string}
match_entry(name, filter) -> boolean
```

`split_path` splits at the last `/`. With no `/` present, `dir` is `null`,
meaning "keep the current listing" — the caller decides what that is, so the
function stays free of UI state. Root is preserved: `/passwd` yields
`{dir: '/', filter: 'passwd'}`.

`match_entry` lowercases both sides and tests for containment. An empty or
whitespace-only filter returns `true`.

The DOM work stays in `webssh/static/js/transfer-ui.js`: the `input` handler,
the debounce timer, the stale-response guard, and rendering.

## Data flow

1. The user types. `transfer-ui.js` calls `split_path`.
2. If `dir` is `null` or equals the directory currently listed, the cached
   entries are re-rendered through `match_entry` immediately, as an
   approximate local pass. Either way, a 250 ms debounce is armed for a
   `/transfer/list` request, since filtering is server-side and the local
   pass is only a stand-in until that response arrives.
3. If typing continues, the timer resets.
4. On fire, `/transfer/list` is called for the new directory.
5. Every request carries an incrementing sequence number. A response whose
   number is not the newest is discarded, so a slow listing of `/usr/bin`
   cannot land after a fast `/tmp` and repaint the wrong directory.
6. The response replaces the cached entries and is rendered through the
   current filter, which may have moved on while the request was in flight.

## Edge cases

- **Failed re-list.** The previous listing stays on screen with an error note
  naming the status. Blanking the list would lose the user's context because
  they typed one wrong character.
- **No matches.** An explicit "No matching files" note, not an empty box, so
  it is distinguishable from a request that failed.
- **Truncation now means "more matches than we will show".** Because the
  server filters before capping, a match that sorts past entry 1000 is still
  found — the original problem, where filtering only searched the first 1000
  names, is gone. The note appears only when the *filtered* result exceeds
  the cap, and says so.
- **The cap bounds the response, not the work.** `listdir_attr` still reads
  the whole directory over SFTP, so an enormous directory is still slow to
  list. Filtering makes files findable, not listing fast. Avoiding that would
  need server-side globbing, which SFTP does not offer.
- **Download uses the box verbatim.** The filter is a view over the listing,
  never a transformation of the path. Pressing Download sends exactly what is
  typed, so a filter fragment left in the box downloads that literal path and
  fails with the server's own 404 — the same as any mistyped path.

## Testing

`tests/js/file-transfer.test.js` covers the two pure functions:

- `split_path`: trailing slash, mid-name, no slash at all, root (`/passwd`),
  empty input, nested paths, and a path that is only `/`.
- `match_entry`: substring rather than prefix, case-insensitivity in both
  directions, empty filter matching everything, and no match.

The debounce, the stale-response guard, and rendering are DOM wiring with no
browser harness available, consistent with the rest of the picker. They are
verified by hand on the dev stack:

- typing narrows the list with no visible lag
- completing a directory and typing `/` re-lists it
- fast typing through several directories leaves the final one displayed
- a truncated directory keeps its warning while filtered
- a failed listing keeps the previous entries and shows the status

## Constraints

- ES5 only: no `const`, `let`, arrow functions, or template literals. CI
  enforces this via `scripts/check_es5.js`.
- No new dependencies.
- `file-transfer.js` stays free of DOM access and jQuery.
