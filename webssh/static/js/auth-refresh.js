/*jslint browser:true */
/*
 * Recovering from a lapsed auth-proxy session without reloading the page.
 *
 * When the proxy's session cookie expires, every request from the page is
 * redirected to the identity provider -- which fetch and XHR cannot follow
 * cross-origin, so they fail with status 0. Reloading would re-authenticate
 * but also close every open terminal. Instead the user signs in again in a
 * popup pointed at auth/done: the proxy walks it through sign-in and back
 * with a fresh cookie, and the landing page posts MESSAGE back here.
 *
 * This file holds the decision logic only; main.js supplies the probe, the
 * popup and the prompt, so it stays unit-testable under `node --test`.
 */

var webssh_auth = (function () {
  'use strict';

  var MESSAGE = 'webssh-auth-ok';
  var CHANNEL = 'webssh-auth';
  var DONE_URL = 'auth/done';

  // Reads a probe response fetched with redirect: 'manual'. Browsers expose
  // the proxy's redirect as an 'opaqueredirect' (status 0), a bare 3xx, or
  // status 0; a proxy may also refuse outright with 401 or 403.
  function is_auth_redirect(resp) {
    return resp.type === 'opaqueredirect' ||
      resp.status === 0 ||
      (resp.status >= 300 && resp.status < 400) ||
      resp.status === 401 ||
      resp.status === 403;
  }

  // deps:
  //   probe()           -> Promise of a manual-redirect fetch response
  //   open_popup(url)   -> the popup window, or null if it was blocked
  //   show_prompt(state) with state.blocked set when the popup was blocked
  //   hide_prompt()
  function make_guard(deps) {
    var expired = false;
    var probing = null;
    var waiting = [];

    function mark_expired() {
      if (expired) {
        return;
      }
      expired = true;
      deps.show_prompt({blocked: false});
    }

    // Resolves true when the session has lapsed. Every request in flight
    // fails at once when it does, so concurrent callers share one probe.
    function check() {
      if (expired) {
        return Promise.resolve(true);
      }
      if (!probing) {
        probing = Promise.resolve().then(deps.probe).then(
          is_auth_redirect,
          // Unreachable server: signing in again would not help.
          function () { return false; }
        ).then(function (lapsed) {
          probing = null;
          if (lapsed) {
            mark_expired();
          }
          return lapsed;
        });
      }
      return probing;
    }

    // Queues fn to run once sign-in completes, or runs it now if the
    // session is live.
    function after_sign_in(fn) {
      if (!expired) {
        fn();
        return;
      }
      waiting.push(fn);
    }

    // Must run from a click: browsers block popups opened any other way.
    function sign_in() {
      if (!deps.open_popup(DONE_URL)) {
        deps.show_prompt({blocked: true});
      }
    }

    // Returns true when data completed a sign-in. The landing page posts
    // over two channels, so the duplicate lands here as a no-op.
    function receive(data) {
      if (data !== MESSAGE || !expired) {
        return false;
      }
      expired = false;
      deps.hide_prompt();
      var queued = waiting;
      waiting = [];
      queued.forEach(function (fn) {
        try {
          fn();
        } catch (e) {
          if (typeof console !== 'undefined') {
            console.error(e);
          }
        }
      });
      return true;
    }

    return {
      check: check,
      mark_expired: mark_expired,
      after_sign_in: after_sign_in,
      sign_in: sign_in,
      receive: receive,
      is_expired: function () { return expired; }
    };
  }

  return {
    MESSAGE: MESSAGE,
    CHANNEL: CHANNEL,
    DONE_URL: DONE_URL,
    is_auth_redirect: is_auth_redirect,
    make_guard: make_guard
  };
}());

if (typeof module !== 'undefined' && module.exports) {
  module.exports = webssh_auth;
}
