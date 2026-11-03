'use strict';

/*
 * End-to-end: clicking an OSC 8 hyperlink (the kind Claude Code and
 * `ls --hyperlink` print) opens it.
 *
 * xterm.js underlined these on hover but, with no linkHandler set, fell back
 * to a confirm() dialog that browsers often suppress, so the click did
 * nothing. Plain URLs were unaffected (the web-links addon opens those).
 *
 * Needs the stack from .claude/skills/run-webssh; `npm run test:e2e` sets
 * it up.
 */

var test = require('node:test');
var assert = require('node:assert');
var connect = require('../../.claude/skills/run-webssh/connect.js');

test.before(function () {
  assert.ok(process.env.WEBSSH_WORKDIR, 'WEBSSH_WORKDIR unset -- run via `npm run test:e2e`');
});

// Clears the screen and prints one OSC 8 link, padded so it is easy to hit,
// on the top row.
async function print_link(page, uri, text) {
  await page.evaluate(function () {
    window.__opened = [];
    window.open = function (u) { window.__opened.push(u); return null; };
    document.querySelector('.terminal-pane.active .xterm-helper-textarea').focus();
  });
  await page.waitForTimeout(300);
  await page.keyboard.press('Enter');
  await connect.run(page, "clear; printf '\\033]8;;" + uri + "\\033\\\\" + text +
                          "\\033]8;;\\033\\\\\\n'");
}

// Moves onto the top row (xterm needs the hover first), then clicks.
async function click_top_row(page) {
  var box = await page.locator('.terminal-pane.active .xterm-screen').boundingBox();
  var x = box.x + 40, y = box.y + 6;
  await page.mouse.move(x - 10, y);
  await page.mouse.move(x, y);
  await page.waitForTimeout(300);
  await page.mouse.click(x, y);
  await page.waitForTimeout(300);
  return page.evaluate(function () { return window.__opened; });
}

test('clicking an OSC 8 link opens its target', async function () {
  var session = await connect.open();
  var page = session.page;
  try {
    await print_link(page, 'https://example.com/osc8-target',
                     'open-me-open-me-open-me-open-me-open-me');
    var opened = await click_top_row(page);
    assert.deepStrictEqual(opened, ['https://example.com/osc8-target']);
  } finally {
    await session.browser.close();
  }
});

test('an OSC 8 link with a non-http scheme does not open', async function () {
  var session = await connect.open();
  var page = session.page;
  try {
    await print_link(page, 'javascript:alert(1)',
                     'do-not-open-do-not-open-do-not-open');
    var opened = await click_top_row(page);
    assert.deepStrictEqual(opened, []);
  } finally {
    await session.browser.close();
  }
});
