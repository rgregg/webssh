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
- **Dropped with the worker.** `Worker.close()` removes any tickets belonging
  to it, so a ticket cannot outlive the session it authorises.

## Validation order on redemption

Every *ticket* failure returns **404** with no detail about which check
failed, so a caller learns nothing about whether a ticket existed, expired, or
belonged to someone else.

The one exception is a valid ticket whose session has since ended, which
returns **410** like the other transfer routes. That distinction leaks
nothing an attacker could not already observe: holding a valid ticket means
they already knew the worker existed.

1. Ticket present and known, else 404.
2. Not expired, else 404 (and drop it).
3. Client IP matches the minting IP, else 404.
4. Consume it — remove before streaming, so a concurrent second use fails.
5. The worker is still live and not closed, else 410.
6. The path comes from the ticket, never from the query string, so a valid
   ticket cannot be redirected at another file.

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
- minting past the cap fails rather than growing the store

Handler tests:

- all three endpoints accept the token in `X-Worker-Id`
- **all three reject the token supplied in the query string**, which is what
  proves the leak is closed rather than merely unused
- redemption failures are 404 and carry no detail about which check failed
- the download path comes from the ticket, so a ticket plus a different
  `?path=` still downloads the ticketed file

## Constraints

- ES5 only under `webssh/static/js/`; enforced by `scripts/check_es5.js`.
- No new dependencies.
- Python: no f-strings, `super(ClassName, self)` form, parenthesised imports.
- `ruff==0.15.6` clean.
