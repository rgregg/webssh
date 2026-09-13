---
name: run-webssh
description: Use when a WebSSH change needs to be seen working in a real browser against a real SSH session - terminal rendering, the tab bar, the transfer dialogs, drag-and-drop, or any CSS whose result you cannot judge from the diff.
---

# Running WebSSH locally

WebSSH's UI only exists once a session connects: the tab bar is hidden until
then, and the transfer dialogs need a host with a working SFTP subsystem.
So a visual check needs three things running — an SSH server, the app, and a
browser driving it. All three are scriptable; none need root or your real keys.

## When to use

- A change to `templates/index.html`, `static/css/main.css`, or the
  `static/js/` UI files that you cannot judge from the diff alone.
- Anything touching upload/download, the picker dialogs, or drag-and-drop.
- Reproducing a layout bug the unit tests cannot see.

**Not** for logic changes covered by `npm test` / `pytest` — those are faster
and already cover `file-transfer.js` and the handler.

## Quick reference

| Step | Command |
|---|---|
| Bring the stack up | `eval "$(.claude/skills/run-webssh/start-stack.sh /tmp/wr)"` |
| Install the driver | `npm install --prefix /tmp/wr playwright` |
| Drive it | `NODE_PATH=/tmp/wr/node_modules node driver.js` |
| Tear it down | `.claude/skills/run-webssh/stop-stack.sh /tmp/wr` |

`start-stack.sh` prints the `WEBSSH_*` environment `connect.js` reads, which is
why it is wrapped in `eval`.

## Writing a driver

```js
const {open, run} = require('/home/ryan/github/rgregg/webssh/.claude/skills/run-webssh/connect.js');

(async () => {
  const {browser, page} = await open();
  // Give the shell a cwd; the transfer dialogs pre-fill from what it reports.
  await run(page, 'cd /home/ryan/github/rgregg/webssh/webssh');

  await page.click('#upload-btn');
  await page.waitForSelector('#transfer-uploader.visible');
  await page.waitForTimeout(1200);          // let the directory listing land
  await page.screenshot({path: '/tmp/wr/shot.png'});

  await browser.close();
})().catch(e => { console.error('FAILED:', e.message); process.exit(1); });
```

Then **read the screenshot**. A driver that asserts and never looks will miss
exactly the class of bug this exists to catch — a review of the upload dialog
passed every assertion while directories were rendering dimmer than the files
they sat above.

## Gotchas

- **`internal-sftp` is required.** `tests/sshserver.py` implements no SFTP
  subsystem, so it cannot drive the transfer UI at all. `start-stack.sh` runs
  a real `sshd` for this reason.
- **`--policy=autoadd`** — the throwaway host key is unknown, and a host-key
  prompt stalls the connect form.
- **Playwright's pinned Chromium is usually absent.** `connect.js` points
  `executablePath` at whatever revision is already cached under
  `~/.cache/ms-playwright`, which avoids a browser download.
- **"Bad host key." in the status bar** means webssh remembered a previous
  throwaway host key. `start-stack.sh` avoids this by keeping the store in
  `$WORKDIR` via `--hostfile`; without that flag webssh writes `./known_hosts`
  in the repo and every later run is refused.
- **`#tab-bar.visible` is not "connected".** The bar appears for a tab that
  failed to connect too. Wait for `.tab-item .tab-status.connected`, and read
  `#status` on timeout — `connect.js` does both and reports the real reason.
- **Headless dismisses `window.confirm`.** An upload onto an existing file
  answers the overwrite prompt with "no" and the row reads `cancelled` — that
  is correct behaviour, not a failure. Clear the destination between runs.
- **Wait after opening a dialog.** The directory listing is a round trip plus a
  250ms debounce; asserting immediately reads an empty list.
- **Port fields are in Advanced.** `#port` is inside the collapsed
  `#advanced-toggle` section; fill it after clicking that.
