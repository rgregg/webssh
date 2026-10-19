'use strict';

/*
 * End-to-end: the "send right-click to the terminal" setting.
 *
 * tmux's mouse mode draws its own right-click menu, which the browser's
 * context menu used to cover. With the setting on, a right-click in the
 * terminal skips the browser menu; Shift+right-click still gets it.
 *
 * Needs the stack from .claude/skills/run-webssh; `npm run test:e2e` sets
 * it up (in user-hosts mode, which the settings pane requires).
 */

var test = require('node:test');
var assert = require('node:assert');
var path = require('path');
var connect = require('../../.claude/skills/run-webssh/connect.js');

var WORKDIR = process.env.WEBSSH_WORKDIR;
var USER_HEADERS = {'X-Authentik-Username': 'e2emenu'};

test.before(function () {
  assert.ok(WORKDIR, 'WEBSSH_WORKDIR unset -- run via `npm run test:e2e`');
});

// Fires a right-click's contextmenu event on the active terminal and
// reports whether the page stopped the browser menu.
function right_click(page, shift) {
  return page.evaluate(function (shift) {
    var target = document.querySelector('.terminal-pane.active .xterm-screen');
    var e = new MouseEvent('contextmenu', {
      bubbles: true, cancelable: true, button: 2, shiftKey: shift
    });
    target.dispatchEvent(e);
    return e.defaultPrevented;
  }, shift);
}

async function set_menu_setting(page, on) {
  await page.click('#settings-btn');
  await page.waitForSelector('.settings-tab[data-section="terminal"]');
  await page.click('.settings-tab[data-section="terminal"]');
  await page.setChecked('#set-suppress-browser-menu', on);
  if (process.env.E2E_SHOTS) {
    await page.screenshot({path: path.join(WORKDIR, 'browser-menu-settings.png')});
  }
  await page.click('#settings-save');
  await page.waitForFunction(function () {
    return document.getElementById('settings-status').textContent === 'Saved';
  }, null, {timeout: 10000});
  // Back to the terminal tab, which stayed open the whole time.
  await page.click('.tab-item:first-child');
  await page.waitForSelector('.terminal-pane.active .xterm-screen');
}

test('the setting hands right-clicks to the terminal, except with Shift',
  async function () {
    var session = await connect.open({headers: USER_HEADERS});
    var page = session.page;
    try {
      assert.strictEqual(await right_click(page, false), false,
                         'browser menu should be untouched by default');

      await set_menu_setting(page, true);
      assert.strictEqual(await right_click(page, false), true,
                         'setting on: the open tab should block the menu');
      assert.strictEqual(await right_click(page, true), false,
                         'Shift+right-click should still get the browser menu');

      await set_menu_setting(page, false);
      assert.strictEqual(await right_click(page, false), false,
                         'turning it off should restore the menu');
    } finally {
      await session.browser.close();
    }
  });
