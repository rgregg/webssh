'use strict';

/*
 * End-to-end: the transfer dialogs' '..' row and their memory of the last
 * folder, per host and per dialog.
 *
 * Needs the stack from .claude/skills/run-webssh; `npm run test:e2e` sets
 * it up. The shell reports its directory over OSC 7 at every prompt, which
 * is what makes "the shell's folder is newer" observable here.
 */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('fs');
var path = require('path');
var connect = require('../../.claude/skills/run-webssh/connect.js');

var WORKDIR = process.env.WEBSSH_WORKDIR;
var TREE = WORKDIR && path.join(WORKDIR, 'tree');

var DIALOGS = {
  download: {button: '#download-btn', dialog: '#transfer-picker'},
  upload: {button: '#upload-btn', dialog: '#transfer-uploader'}
};

test.before(function () {
  assert.ok(WORKDIR, 'WEBSSH_WORKDIR unset -- run via `npm run test:e2e`');
  fs.rmSync(TREE, {recursive: true, force: true});
  fs.mkdirSync(path.join(TREE, 'a', 'b', 'c'), {recursive: true});
  fs.mkdirSync(path.join(TREE, 'other'), {recursive: true});
  fs.writeFileSync(path.join(TREE, 'a', 'b', 'file.txt'), 'x');
});

async function shell(page, command) {
  await page.evaluate(function () {
    document.querySelector('.xterm-helper-textarea').focus();
  });
  await page.waitForTimeout(300);
  // The first keystroke after a programmatic focus can be dropped; a bare
  // Enter absorbs that without corrupting the command.
  await page.keyboard.press('Enter');
  await connect.run(page, command);
}

// Opens a dialog and waits for its first listing. Returns the directory it
// settled on, without the trailing slash.
async function open_dialog(page, kind) {
  var d = DIALOGS[kind];
  await page.click(d.button);
  await page.waitForSelector(d.dialog + '.visible');
  await page.waitForSelector(d.dialog + ' .picker-item, ' + d.dialog +
    ' .picker-note', {timeout: 5000});
  await page.waitForTimeout(400);
  return (await page.inputValue(d.dialog + ' .picker-path')).replace(/\/$/, '');
}

async function close_dialog(page, kind) {
  await page.click(DIALOGS[kind].dialog + ' .picker-cancel');
  await page.waitForSelector(DIALOGS[kind].dialog + '.visible', {state: 'hidden'});
}

async function click_row(page, kind, text) {
  var d = DIALOGS[kind];
  await page.click(d.dialog + ' .picker-item >> text="' + text + '"');
  await page.waitForTimeout(700);  // 250ms debounce plus the round trip
}

async function rows(page, kind) {
  return page.$$eval(DIALOGS[kind].dialog + ' .picker-item', function (els) {
    return els.map(function (e) { return e.textContent; });
  });
}

test('the .. row walks up a level and is hidden at the root and while filtering',
  async function () {
    var session = await connect.open();
    var page = session.page;
    try {
      await shell(page, 'cd ' + path.join(TREE, 'a', 'b'));
      assert.strictEqual(await open_dialog(page, 'download'),
        path.join(TREE, 'a', 'b'));
      assert.strictEqual((await rows(page, 'download'))[0], '../');

      await click_row(page, 'download', '../');
      assert.strictEqual(await page.inputValue('#transfer-picker .picker-path'),
        path.join(TREE, 'a') + '/');
      assert.ok((await rows(page, 'download')).indexOf('b/') !== -1);

      // Filtering is a search of this directory; '..' is not a match.
      await page.fill('#transfer-picker .picker-path', path.join(TREE, 'a') + '/b');
      await page.waitForTimeout(700);
      assert.deepStrictEqual(await rows(page, 'download'), ['b/']);

      await page.fill('#transfer-picker .picker-path', '/');
      await page.waitForTimeout(700);
      assert.strictEqual((await rows(page, 'download')).indexOf('../'), -1);
      await close_dialog(page, 'download');
    } finally {
      await session.browser.close();
    }
  });

test('each dialog reopens where it was left until the shell moves on',
  async function () {
    var session = await connect.open();
    var page = session.page;
    try {
      await shell(page, 'cd ' + TREE);

      // Browse the downloader into a/b/c and leave.
      assert.strictEqual(await open_dialog(page, 'download'), TREE);
      await click_row(page, 'download', 'a/');
      await click_row(page, 'download', 'b/');
      await click_row(page, 'download', 'c/');
      await close_dialog(page, 'download');

      // Browse the uploader somewhere else.
      assert.strictEqual(await open_dialog(page, 'upload'), TREE);
      await click_row(page, 'upload', 'other/');
      await close_dialog(page, 'upload');

      // No command since: each dialog's own last folder is the freshest.
      assert.strictEqual(await open_dialog(page, 'download'),
        path.join(TREE, 'a', 'b', 'c'));
      await close_dialog(page, 'download');
      assert.strictEqual(await open_dialog(page, 'upload'),
        path.join(TREE, 'other'));
      await close_dialog(page, 'upload');

      // The shell reporting a new directory outdates both.
      await shell(page, 'cd ' + path.join(TREE, 'a'));
      assert.strictEqual(await open_dialog(page, 'download'), path.join(TREE, 'a'));
      await close_dialog(page, 'download');
    } finally {
      await session.browser.close();
    }
  });

test('the memory survives a reload and skips a folder that is gone',
  async function () {
    var session = await connect.open();
    var page = session.page;
    try {
      await shell(page, 'cd ' + TREE);
      await open_dialog(page, 'download');
      await click_row(page, 'download', 'other/');
      await close_dialog(page, 'download');

      // A fresh page and connection to the same host. The shell's first
      // prompt reports its login directory, so browse after it to make the
      // remembered folder the newer one.
      await page.reload();
      await page.waitForSelector('#connect');
      await page.fill('#hostname', '127.0.0.1');
      if (!await page.isVisible('#port')) {
        await page.click('#advanced-toggle');
      }
      await page.fill('#port', process.env.WEBSSH_SSH_PORT || '2222');
      await page.fill('#username', require('os').userInfo().username);
      await page.setInputFiles('#privatekey', process.env.WEBSSH_KEY);
      await page.click('.btn-connect');
      await page.waitForSelector('.tab-item .tab-status.connected', {timeout: 20000});
      await page.waitForTimeout(2500);

      var stored = await page.evaluate(function () {
        return window.localStorage.getItem('webssh_transfer_dirs');
      });
      assert.ok(stored && stored.indexOf(path.join(TREE, 'other')) !== -1,
        'the folder is stored across the reload');

      // Remove the remembered folder: the dialog must fall back rather
      // than open on an error.
      fs.rmSync(path.join(TREE, 'other'), {recursive: true, force: true});
      await page.evaluate(function (dir) {
        var store = JSON.parse(window.localStorage.getItem('webssh_transfer_dirs'));
        Object.keys(store).forEach(function (host) {
          store[host].download = {dir: dir, at: Date.now() + 60000};
        });
        window.localStorage.setItem('webssh_transfer_dirs', JSON.stringify(store));
      }, path.join(TREE, 'other'));

      var opened = await open_dialog(page, 'download');
      assert.notStrictEqual(opened, path.join(TREE, 'other'));
      assert.strictEqual(await page.$$eval('#transfer-picker .picker-note.is-error',
        function (els) { return els.length; }), 0, 'no error is shown');
      await close_dialog(page, 'download');
    } finally {
      fs.mkdirSync(path.join(TREE, 'other'), {recursive: true});
      await session.browser.close();
    }
  });
