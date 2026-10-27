'use strict';

/*
 * End-to-end: pasting into the terminal.
 *
 * An image-only paste uploads the image to ~/.cache/webssh-paste on the
 * host and pastes its path, so Claude Code running there can attach it. A
 * text paste must still reach the shell exactly as before.
 *
 * The test sshd runs as the current user, so the image lands in your real
 * ~/.cache/webssh-paste; the test deletes the one file it made.
 *
 * Needs the stack from .claude/skills/run-webssh; `npm run test:e2e` sets
 * it up.
 */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('fs');
var path = require('path');
var connect = require('../../.claude/skills/run-webssh/connect.js');

var WORKDIR = process.env.WEBSSH_WORKDIR;
var PNG = path.join(__dirname, '../../preview/login.png');

test.before(function () {
  assert.ok(WORKDIR, 'WEBSSH_WORKDIR unset -- run via `npm run test:e2e`');
});

// Fires a paste on xterm's textarea, the element a real Cmd+V targets.
// opts.type sets the image's type; opts.html adds a text/html entry, as a
// browser's "Copy image" does.
async function paste(page, kind, payload, opts) {
  await page.evaluate(function (args) {
    var o = args[2] || {};
    var dt = new DataTransfer();
    if (args[0] === 'text') {
      dt.setData('text/plain', args[1]);
    } else {
      if (o.html) {
        dt.setData('text/html', o.html);
      }
      var bin = Uint8Array.from(atob(args[1]), function (c) {
        return c.charCodeAt(0);
      });
      var type = o.type || 'image/png';
      dt.items.add(new File([bin], 'image', {type: type}));
    }
    var ta = document.querySelector('.terminal-pane.active .xterm-helper-textarea');
    ta.focus();
    ta.dispatchEvent(new ClipboardEvent('paste', {
      clipboardData: dt, bubbles: true, cancelable: true
    }));
  }, [kind, payload, opts]);
}

// Has the shell read one line into a file, so the test sees exactly what
// the paste delivered.
async function capture_line(page, out) {
  await connect.run(page, "read L; printf '%s' \"$L\" > " + out);
}

test('text paste reaches the shell unchanged', async function () {
  var session = await connect.open();
  var out = path.join(WORKDIR, 'paste-text.out');
  try {
    await session.page.click('.xterm');
    await capture_line(session.page, out);
    await paste(session.page, 'text', 'plain text paste');
    await session.page.keyboard.press('Enter');
    await session.page.waitForTimeout(800);
    assert.strictEqual(fs.readFileSync(out, 'utf8'), 'plain text paste');
  } finally {
    await session.browser.close();
  }
});

test('image paste uploads the image and pastes its path', async function () {
  var session = await connect.open();
  var out = path.join(WORKDIR, 'paste-image.out');
  var uploaded = null;
  try {
    await session.page.click('.xterm');
    await capture_line(session.page, out);
    await paste(session.page, 'image', fs.readFileSync(PNG).toString('base64'));
    await session.page.waitForSelector('.transfer-status:has-text("uploaded")',
                                       {timeout: 10000});
    await session.page.waitForTimeout(500);
    await session.page.keyboard.press('Enter');
    await session.page.waitForTimeout(800);

    uploaded = fs.readFileSync(out, 'utf8');
    assert.match(uploaded,
      /\/\.cache\/webssh-paste\/paste-\d{8}-\d{6}-\d{3}\.png$/);
    assert.ok(fs.readFileSync(uploaded).equals(fs.readFileSync(PNG)),
              'uploaded bytes differ from the pasted image');
    // Screenshots can be private: the folder is owner-only.
    assert.strictEqual(fs.statSync(path.dirname(uploaded)).mode & 0o777, 0o700);
  } finally {
    if (uploaded) {
      fs.rmSync(uploaded, {force: true});
    }
    await session.browser.close();
  }
});

test('an image copied from a web page (with its HTML) still uploads', async function () {
  // The bytes are a PNG; only the declared type matters to the paste path.
  var session = await connect.open();
  var out = path.join(WORKDIR, 'paste-webp.out');
  var uploaded = null;
  try {
    await session.page.click('.xterm');
    await capture_line(session.page, out);
    await paste(session.page, 'image', fs.readFileSync(PNG).toString('base64'),
                {type: 'image/webp',
                 html: '<img src="https://example.com/a.webp">'});
    await session.page.waitForSelector('.transfer-status:has-text("uploaded")',
                                       {timeout: 10000});
    await session.page.waitForTimeout(500);
    await session.page.keyboard.press('Enter');
    await session.page.waitForTimeout(800);

    uploaded = fs.readFileSync(out, 'utf8');
    assert.match(uploaded,
      /\/\.cache\/webssh-paste\/paste-\d{8}-\d{6}-\d{3}\.webp$/);
  } finally {
    if (uploaded) {
      fs.rmSync(uploaded, {force: true});
    }
    await session.browser.close();
  }
});
