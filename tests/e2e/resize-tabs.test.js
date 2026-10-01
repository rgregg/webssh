'use strict';

/*
 * End-to-end: resizing the window with more than one terminal tab open.
 *
 * Only the active tab used to be refitted, which left the others at the old
 * size twice over: their oversized screens overflowed the page, and the
 * host behind them never heard about the new size.
 *
 * Needs the stack from .claude/skills/run-webssh; `npm run test:e2e` sets
 * it up.
 */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('fs');
var os = require('os');
var path = require('path');
var connect = require('../../.claude/skills/run-webssh/connect.js');

var WORKDIR = process.env.WEBSSH_WORKDIR;
var STTY = WORKDIR && path.join(WORKDIR, 'stty.txt');

test.before(function () {
  assert.ok(WORKDIR, 'WEBSSH_WORKDIR unset -- run via `npm run test:e2e`');
});

// Connects a second tab; connect.open() leaves the first one connected.
async function open_second_tab(page) {
  await page.click('#new-tab-btn');
  await page.fill('#hostname', '127.0.0.1');
  await page.fill('#port', process.env.WEBSSH_SSH_PORT);
  await page.fill('#username', os.userInfo().username);
  await page.setInputFiles('#privatekey', process.env.WEBSSH_KEY);
  await page.click('.btn-connect');
  await page.waitForFunction(function () {
    return document.querySelectorAll('.tab-item .tab-status.connected').length === 2;
  }, null, {timeout: 20000});
  await page.waitForTimeout(2000);
}

// The size the host believes the active tab's terminal is, as "rows cols".
async function remote_size(page) {
  fs.rmSync(STTY, {force: true});
  await page.evaluate(function () {
    document.querySelector('.terminal-pane.active .xterm-helper-textarea').focus();
  });
  await page.waitForTimeout(300);
  // The first keystroke after a programmatic focus can be dropped; a bare
  // Enter absorbs that without corrupting the command.
  await page.keyboard.press('Enter');
  await connect.run(page, 'stty size > ' + STTY);
  return fs.readFileSync(STTY, 'utf8').trim();
}

test('a window resize refits every tab, not only the active one',
  async function () {
    var session = await connect.open();
    var page = session.page;
    try {
      await open_second_tab(page);
      var before = await remote_size(page);

      await page.setViewportSize({width: 800, height: 500});
      await page.waitForTimeout(600);

      var overflow = await page.evaluate(function () {
        var doc = document.documentElement;
        return {width: doc.scrollWidth - window.innerWidth,
                height: doc.scrollHeight - window.innerHeight};
      });
      assert.deepStrictEqual(overflow, {width: 0, height: 0},
        'the hidden tab must not push the page past the window');

      var active = await remote_size(page);
      assert.notStrictEqual(active, before, 'the shrink reached the active tab');

      // Both panes are the same size, so the tab that was hidden during the
      // resize must report what the active one did.
      await page.click('.tab-item:nth-child(1)');
      await page.waitForTimeout(600);
      assert.strictEqual(await remote_size(page), active,
        'the host behind the hidden tab was told the new size');
    } finally {
      await session.browser.close();
    }
  });
