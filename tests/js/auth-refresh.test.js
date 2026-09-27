'use strict';

var test = require('node:test');
var assert = require('node:assert');
var auth = require('../../webssh/static/js/auth-refresh.js');

test('is_auth_redirect treats redirects and auth refusals as expiry', function () {
  assert.strictEqual(auth.is_auth_redirect({type: 'opaqueredirect', status: 0}), true);
  assert.strictEqual(auth.is_auth_redirect({type: 'basic', status: 0}), true);
  assert.strictEqual(auth.is_auth_redirect({type: 'basic', status: 302}), true);
  assert.strictEqual(auth.is_auth_redirect({type: 'basic', status: 401}), true);
  assert.strictEqual(auth.is_auth_redirect({type: 'basic', status: 403}), true);
});

test('is_auth_redirect leaves a live session alone', function () {
  assert.strictEqual(auth.is_auth_redirect({type: 'basic', status: 200}), false);
  // A server error is a server problem, not a lapsed sign-in.
  assert.strictEqual(auth.is_auth_redirect({type: 'basic', status: 502}), false);
});

function harness(probe_result) {
  var calls = {probes: 0, shown: [], hidden: 0, opened: []};
  var popup = {};
  var guard = auth.make_guard({
    probe: function () {
      calls.probes += 1;
      if (probe_result instanceof Error) {
        return Promise.reject(probe_result);
      }
      return Promise.resolve(probe_result);
    },
    open_popup: function (url) {
      calls.opened.push(url);
      return calls.popup_blocked ? null : popup;
    },
    show_prompt: function (state) { calls.shown.push(state); },
    hide_prompt: function () { calls.hidden += 1; }
  });
  return {guard: guard, calls: calls};
}

test('check prompts for sign-in when the probe is redirected', async function () {
  var h = harness({type: 'opaqueredirect', status: 0});
  assert.strictEqual(await h.guard.check(), true);
  assert.strictEqual(h.guard.is_expired(), true);
  assert.deepStrictEqual(h.calls.shown, [{blocked: false}]);
});

test('check stays quiet when the session is live', async function () {
  var h = harness({type: 'basic', status: 200});
  assert.strictEqual(await h.guard.check(), false);
  assert.strictEqual(h.guard.is_expired(), false);
  assert.deepStrictEqual(h.calls.shown, []);
});

test('check treats an unreachable server as not expired', async function () {
  // The server being down is not something signing in again fixes.
  var h = harness(new TypeError('Failed to fetch'));
  assert.strictEqual(await h.guard.check(), false);
  assert.deepStrictEqual(h.calls.shown, []);
});

test('concurrent checks share one probe and one prompt', async function () {
  // A lapsed session fails every in-flight request at once; they must not
  // each probe the server and stack prompts.
  var h = harness({type: 'opaqueredirect', status: 0});
  var results = await Promise.all([h.guard.check(), h.guard.check(), h.guard.check()]);
  assert.deepStrictEqual(results, [true, true, true]);
  assert.strictEqual(h.calls.probes, 1);
  assert.strictEqual(h.calls.shown.length, 1);
  // Once known expired, no further probing until sign-in completes.
  await h.guard.check();
  assert.strictEqual(h.calls.probes, 1);
});

test('sign_in opens the landing page in a popup', function () {
  var h = harness({type: 'basic', status: 200});
  h.guard.mark_expired();
  h.guard.sign_in();
  assert.deepStrictEqual(h.calls.opened, [auth.DONE_URL]);
});

test('sign_in reports a blocked popup instead of failing silently', function () {
  var h = harness({type: 'basic', status: 200});
  h.guard.mark_expired();
  h.calls.popup_blocked = true;
  h.guard.sign_in();
  assert.deepStrictEqual(h.calls.shown, [{blocked: false}, {blocked: true}]);
});

test('receive clears the prompt and runs queued retries once', function () {
  var h = harness({type: 'basic', status: 200});
  var ran = [];
  h.guard.mark_expired();
  h.guard.after_sign_in(function () { ran.push('a'); });
  h.guard.after_sign_in(function () { ran.push('b'); });
  assert.deepStrictEqual(ran, []);

  assert.strictEqual(h.guard.receive(auth.MESSAGE), true);
  assert.deepStrictEqual(ran, ['a', 'b']);
  assert.strictEqual(h.calls.hidden, 1);
  assert.strictEqual(h.guard.is_expired(), false);

  // The same message over the second channel is a duplicate, not a
  // second sign-in.
  assert.strictEqual(h.guard.receive(auth.MESSAGE), false);
  assert.deepStrictEqual(ran, ['a', 'b']);
  assert.strictEqual(h.calls.hidden, 1);
});

test('receive ignores unrelated messages', function () {
  var h = harness({type: 'basic', status: 200});
  var ran = 0;
  h.guard.mark_expired();
  h.guard.after_sign_in(function () { ran += 1; });
  assert.strictEqual(h.guard.receive('something-else'), false);
  assert.strictEqual(h.guard.receive({data: auth.MESSAGE}), false);
  assert.strictEqual(ran, 0);
  assert.strictEqual(h.guard.is_expired(), true);
});

test('a failing retry does not stop the ones after it', function () {
  var h = harness({type: 'basic', status: 200});
  var ran = [];
  h.guard.mark_expired();
  h.guard.after_sign_in(function () { throw new Error('boom'); });
  h.guard.after_sign_in(function () { ran.push('second'); });
  h.guard.receive(auth.MESSAGE);
  assert.deepStrictEqual(ran, ['second']);
});

test('after_sign_in runs immediately when the session is live', function () {
  var h = harness({type: 'basic', status: 200});
  var ran = 0;
  h.guard.after_sign_in(function () { ran += 1; });
  assert.strictEqual(ran, 1);
});
