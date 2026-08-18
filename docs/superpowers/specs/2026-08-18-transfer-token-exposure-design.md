# Keeping the Worker Token Out of URLs — Design

The worker token authorises every transfer request. It currently travels in
the query string, which puts it in the browser's download history and in
server access logs.

## The problem

The token is a session-long credential: anyone holding it, from the same
client IP, can list directories, download files, and upload files on that SSH
session for as long as it lives.

Three places leak it today:

| Request | Trigger | Where it lands |
| --- | --- | --- |
| `/transfer/download?id=` | `window.location` | The browser's **download manager**, permanently, visible long after the session ends |
| `/transfer/list?id=` | XHR | Server access logs |
| `/transfer/upload?id=` | `fetch` | Server access logs |

The download case is the worst: it persists in the user's own browser, not
merely in logs the operator already controls.

## Two mechanisms, because the cases differ

A browser-initiated navigation cannot set request headers; an XHR can. That
distinction, not preference, is what splits the design.

### `list` and `upload`: move the token to a header

Both are already XHR/`fetch`, so `X-Worker-Id: <token>` replaces `?id=`. No
URL exposure, no server-side state, no extra round trip.

This also strengthens CSRF posture. A custom header cannot be set by a simple
cross-origin form post, so these stop being simple requests. It does not
replace the existing XSRF check on upload, which stays.

### `download`: a one-time ticket

```
POST /transfer/ticket      X-Worker-Id header, {"path": "..."} body, XSRF required
  -> {"ticket": "<43 url-safe chars>", "expires_in": 60}

GET  /transfer/download?ticket=<ticket>
  -> validates, consumes, streams
```

The ticket is bound to **worker, path, and client IP**, is **single-use**, and
expires after **60 seconds**.

A ticket recovered from download history is already spent. Even an unspent one
authorises a single download of an already-known path, from one IP, for one
minute — it is not a session credential.

### Single-use costs nothing here

Single-use would normally break resumed downloads. It does not, because the
download handler does not support `Range`: an interrupted download already
restarts from zero.

Stated explicitly so that anyone adding `Range` support later notices the
interaction rather than discovering it through broken resumes.

## The ticket store

A module-level dict in `webssh/worker.py`, beside `live_workers`:

```
tickets = {}   # ticket -> {'worker_id', 'path', 'ip', 'expires'}
```

- **Swept on mint.** Every mint drops expired entries first, so the store
  cannot accumulate abandoned tickets. There is no background timer.
- **Hard cap.** `MAX_TICKETS = 256`. When the store is full *after* sweeping,
  minting fails with 503 rather than growing without bound. A legitimate user
  holds at most a handful at once; hitting the cap means something is looping.
- **Per-worker cap.** `MAX_TICKETS_PER_WORKER = 8`. The global cap alone lets
  one authenticated session (or a looping client) consume the entire budget
  and return 503 to every other user's `/transfer/ticket` for up to
  `TICKET_TTL`; the per-worker cap bounds one session's share of it. Both
  caps surface as the same 503 — the caller does not need to know which one
  it hit.
- **Path length limit at mint.** `MAX_TICKET_PATH_LENGTH = 4096` (PATH_MAX on
  Linux). A path longer than that is rejected with 400 and never stored,
  so an oversized `path` cannot combine with the ticket cap to retain
  disproportionate memory for up to `TICKET_TTL` seconds.
- **Dropped with the worker.** `Worker.close()` removes any tickets belonging
  to it, so a ticket cannot outlive the session it authorises.

## Validation order on redemption

Every *ticket* failure returns **404** with no detail about which check
failed, so a caller learns nothing about whether a ticket existed, expired, or
belonged to someone else.

The concurrency cap is checked against the ticket's worker *before* the
ticket is consumed, so a request rejected with 429 leaves the ticket usable
for a retry rather than spending a single-use credential on a rejection.

1. Ticket present and known, else 404.
2. Not expired, else 404.
3. Client IP matches the minting IP, else 404.
4. The worker is still live, else 404.
5. The worker is not at the concurrency cap, else 429 — checked before the
   ticket is consumed.
6. Consume it — remove before streaming, so a concurrent second use fails.
7. The path comes from the ticket, never from the query string, so a valid
   ticket cannot be redirected at another file.

The handler also has a 410 branch ("the terminal session ended") for a
worker found not live/closed, matching the other transfer routes. It is
defence in depth, not reachable behaviour: `Worker.close()` unregisters the
worker from `live_workers` and drops its tickets in the same step, so a
ticket for an ended session always fails redemption at step 1 or 4 as an
unknown/unresolvable ticket (404), never reaches the worker-closed check.
The branch is kept for a future code path that might set `closed` without
also dropping tickets.

## What does not change

- **`ws?id=` keeps its token in the URL.** It predates this feature, it works
  differently — the token is consumed at attach and nulled in `clients` — and
  changing it would touch the connection path. Recorded as a decision, not an
  oversight.
- **No backward compatibility for `?id=`** on the three transfer routes.
  Accepting both would leave the leak in place for any caller that kept using
  it. The only consumers are this project's own JavaScript.
- The streaming, concurrency cap, cancellation, and idle-timeout suppression
  behaviours are untouched.

## Client changes

`file-transfer.js` loses `id` from its URL builders and gains
`ticket_url(ticket)`. `transfer-ui.js` sends `X-Worker-Id` on the list and
upload calls, and the download button becomes: mint a ticket, then set
`window.location` to the ticket URL.

A failed mint reports through the same path as any other transfer failure; the
user sees the status rather than a silently dead button.

## Testing

Ticket lifecycle, tested directly against the store:

- mint then consume returns the bound worker and path
- an expired ticket is refused and dropped
- a consumed ticket cannot be used twice
- a ticket presented from a different client IP is refused
- an unknown ticket is refused
- `Worker.close()` drops that worker's tickets and leaves others alone
- the sweep reclaims expired entries so the cap is not reached by abandoned
  tickets
- minting past the global cap fails rather than growing the store
- minting past the per-worker cap fails while a different worker can still
  mint
- a path over `MAX_TICKET_PATH_LENGTH` is rejected at the API boundary
  rather than stored

Handler tests:

- all three endpoints accept the token in `X-Worker-Id`
- **all four routes reject the token/ticket supplied via `?id=`**, which is
  what proves the leak is closed rather than merely unused (including
  `/transfer/ticket` itself)
- redemption failures are 404 and carry no detail about which check failed
  (the body does not distinguish an unknown, expired, or mismatched ticket)
- the download path comes from the ticket, so a ticket plus a different
  `?path=` still downloads the ticketed file
- a non-string `path` in the mint payload is rejected with 400 rather than
  minting a ticket that later 500s
- a download rejected with 429 (concurrency cap) leaves the ticket
  redeemable for a retry
- a closed session's ticket now fails redemption via `Worker.close()`
  (404, an unresolvable ticket), not by setting `worker.closed` directly

## Constraints

- ES5 only under `webssh/static/js/`; enforced by `scripts/check_es5.js`.
- No new dependencies.
- Python: no f-strings, `super(ClassName, self)` form, parenthesised imports.
- `ruff==0.15.6` clean.
