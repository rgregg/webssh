'use strict';

/*
 * End-to-end: a lapsed auth-proxy session is recovered in a popup, and open
 * terminals survive it.
 *
 * Needs the stack from .claude/skills/run-webssh running in user-hosts mode
 * and Playwright installed; `npm run test:e2e` sets up both. Not part of
 * `npm test`.
 *
 * The auth proxy is simulated with request routing. While `expired` is set,
 * every request to the app is redirected to an identity provider on another
 * origin -- exactly what the Authentik outpost does, and what XHR and fetch
 * cannot follow. The popup's navigation to auth/done stands in for the
 * provider's sign-in round trip: it clears `expired` and lands back on the
 * real auth/done page.
 */

var test = require('node:test');
var assert = require('node:assert');
var fs = require('fs');
var path = require('path');
var connect = require('../../.claude/skills/run-webssh/connect.js');

var APP = process.env.WEBSSH_URL || 'http://127.0.0.1:8899';
var IDP = 'http://localhost:1/authorize';
var WORKDIR = process.env.WEBSSH_WORKDIR;
var USER_HEADERS = {'X-Authentik-Username': 'e2euser'};

// Routes every app request through a switchable auth proxy. Returns the
// switch and counters the tests assert on.
async function install_proxy(page) {
  var proxy = {expired: false, sign_ins: 0, settings_saved: 0};
  var app_origin = new URL(APP).origin;

  await page.context().route(function (url) {
    return url.origin === app_origin;
  }, function (route) {
    var request = route.request();
    var url = new URL(request.url());

    if (!proxy.expired) {
      if (url.pathname === '/api/settings' && request.method() === 'PUT') {
        return route.fetch().then(function (response) {
          if (response.ok()) {
            proxy.settings_saved += 1;
          }
          return route.fulfill({response: response});
        });
      }
      return route.continue();
    }

    if (url.pathname === '/auth/done' && request.isNavigationRequest()) {
      // The identity provider: sign in, then send the popup back.
      proxy.sign_ins += 1;
      proxy.expired = false;
      return route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: '<p>identity provider</p><script>' +
          'setTimeout(function () { location.replace("/auth/done"); }, 200);' +
          '</script>'
      });
    }
    return route.fulfill({status: 302, headers: {location: IDP}});
  });
  return proxy;
}

async function sign_in_via_popup(page) {
  var popup_promise = page.waitForEvent('popup');
  await page.click('#auth-prompt .auth-prompt-sign-in');
  var popup = await popup_promise;
  if (!popup.isClosed()) {
    await popup.waitForEvent('close', {timeout: 10000});
  }
  await page.waitForSelector('#auth-prompt:not(.visible)', {timeout: 5000});
}

// Proves the shell is still attached by having it write a file. The
// terminal draws with WebGL, so its text is not in the DOM to read.
async function assert_shell_alive(page, name) {
  var marker = path.join(WORKDIR, name);
  fs.rmSync(marker, {force: true});
  await page.evaluate(function () {
    document.querySelector('.xterm-helper-textarea').focus();
  });
  await page.waitForTimeout(300);
  // The first keystroke after a programmatic focus can be dropped; a bare
  // Enter absorbs that without corrupting the command.
  await page.keyboard.press('Enter');
  await page.keyboard.type('echo alive > ' + marker + '\n');
  for (var i = 0; i < 20 && !fs.existsSync(marker); i++) {
    await page.waitForTimeout(250);
  }
  assert.strictEqual(fs.readFileSync(marker, 'utf8').trim(), 'alive');
}

async function connected_tabs(page) {
  return page.$$eval('.tab-item .tab-status.connected', function (els) {
    return els.length;
  });
}

async function fill_connect_form(page) {
  await page.waitForSelector('#connect', {state: 'visible'});
  await page.fill('#hostname', '127.0.0.1');
  if (!await page.isVisible('#port')) {
    await page.click('#advanced-toggle');
  }
  await page.fill('#port', process.env.WEBSSH_SSH_PORT || '2222');
  await page.fill('#username', require('os').userInfo().username);
  await page.setInputFiles('#privatekey', process.env.WEBSSH_KEY);
}

test.before(function () {
  assert.ok(WORKDIR, 'WEBSSH_WORKDIR unset -- run via `npm run test:e2e`');
});

test('a background request on a lapsed session is recovered without a reload',
  async function () {
    var session = await connect.open({headers: USER_HEADERS});
    var page = session.page;
    try {
      var proxy = await install_proxy(page);
      var loads = 0;
      page.on('load', function () { loads += 1; });

      proxy.expired = true;
      // The download dialog lists a directory: the first request to meet
      // the lapsed session.
      await page.click('#download-btn');
      await page.waitForSelector('#auth-prompt.visible', {timeout: 5000});
      assert.match(await page.textContent('#auth-prompt .auth-prompt-text'),
        /sign-in has expired/);
      await page.click('#transfer-picker .picker-cancel');

      await sign_in_via_popup(page);

      assert.strictEqual(proxy.sign_ins, 1);
      assert.strictEqual(loads, 0, 'the page must not reload');
      assert.strictEqual(await page.$$eval('.tab-item', function (t) {
        return t.length;
      }), 1, 'the sign-in signal must not open a tab');
      assert.strictEqual(await connected_tabs(page), 1);
      await assert_shell_alive(page, 'alive-background.txt');
    } finally {
      await session.browser.close();
    }
  });

test('a connect on a lapsed session keeps other terminals and retries the settings save',
  async function () {
    var session = await connect.open({headers: USER_HEADERS});
    var page = session.page;
    try {
      var proxy = await install_proxy(page);
      // Let the first connect's own settings save land before expiring.
      await page.waitForTimeout(1500);
      var saved_before = proxy.settings_saved;

      proxy.expired = true;
      await page.click('#new-tab-btn');
      await fill_connect_form(page);
      await page.click('.btn-connect');

      await page.waitForSelector('#auth-prompt.visible', {timeout: 5000});
      await page.waitForFunction(function () {
        return /Sign-in expired/.test(document.querySelector('#status').textContent);
      }, null, {timeout: 5000});
      // The connect stored its form values, arming a settings save; give it
      // time to fail against the lapsed session.
      await page.waitForTimeout(2000);
      assert.strictEqual(proxy.settings_saved, saved_before);
      assert.strictEqual(await connected_tabs(page), 1,
        'the first terminal must survive');

      await sign_in_via_popup(page);

      // The failed save was queued for after sign-in (1s debounce).
      await page.waitForTimeout(2000);
      assert.ok(proxy.settings_saved > saved_before,
        'the settings save must be retried after sign-in');

      // And the connect that failed now goes through.
      await fill_connect_form(page);
      await page.click('.btn-connect');
      await page.waitForFunction(function () {
        return document.querySelectorAll('.tab-item .tab-status.connected').length === 2;
      }, null, {timeout: 20000});
    } finally {
      await session.browser.close();
    }
  });

test('a blocked sign-in popup is reported', async function () {
  var session = await connect.open({headers: USER_HEADERS});
  var page = session.page;
  try {
    var proxy = await install_proxy(page);
    await page.evaluate(function () {
      window.open = function () { return null; };
    });

    proxy.expired = true;
    await page.click('#download-btn');
    await page.waitForSelector('#auth-prompt.visible', {timeout: 5000});
    await page.click('#transfer-picker .picker-cancel');
    await page.click('#auth-prompt .auth-prompt-sign-in');

    assert.match(await page.textContent('#auth-prompt .auth-prompt-text'),
      /blocked/);
    assert.strictEqual(await page.isVisible('#auth-prompt'), true);
  } finally {
    await session.browser.close();
  }
});
