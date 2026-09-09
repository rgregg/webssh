'use strict';

var test = require('node:test');
var assert = require('node:assert');
var fs = require('node:fs');
var path = require('node:path');
var vm = require('node:vm');

var ft = require('../../webssh/static/js/file-transfer.js');

// transfer-ui.js is a browser script, not a module: it needs jQuery, a tray
// element and fetch. Rather than pull in a DOM library (this suite has no
// dependencies by design), stub the handful of jQuery calls it actually
// makes. Each fake node records what was done to it, which is all the
// assertions below need.
function fake_node() {
  var node = {
    children_list: [],
    status_text: null,
    handlers: {},
    removed: false
  };
  node.append = function (child) {
    node.children_list.push(child);
    return node;
  };
  node.find = function (selector) {
    if (selector === '.transfer-status') {
      return {
        text: function (value) {
          if (value === undefined) {
            return node.status_text;
          }
          node.status_text = value;
          return this;
        }
      };
    }
    // .transfer-cancel
    return {
      off: function () {
        return this;
      },
      on: function (event, fn) {
        node.handlers[event] = fn;
        return this;
      },
      remove: function () {
        return this;
      }
    };
  };
  node.addClass = function () {
    return node;
  };
  node.removeClass = function () {
    return node;
  };
  node.children = function () {
    return node.children_list;
  };
  node.remove = function () {
    node.removed = true;
    return node;
  };
  node.fadeOut = function (ms, fn) {
    if (fn) {
      fn();
    }
    return node;
  };
  node.text = function () {
    return node;
  };
  return node;
}

function load_ui(fetch_impl, timers) {
  var tray = fake_node();
  var jq = function () {
    return tray;
  };
  var sandbox = {
    window: {
      prompt: function (message, value) {
        return value;
      },
      confirm: function () {
        return false;
      },
      wssh: {get_xsrf_token: function () {
        return 'x';
      }}
    },
    $: jq,
    webssh_transfer: ft,
    fetch: fetch_impl,
    AbortController: AbortController,
    setTimeout: timers ? timers.set : setTimeout,
    clearTimeout: timers ? timers.clear : clearTimeout,
    console: console
  };
  var src = fs.readFileSync(
    path.join(__dirname, '../../webssh/static/js/transfer-ui.js'), 'utf8'
  );
  vm.runInNewContext(src, sandbox);
  return sandbox.webssh_transfer_ui;
}

// A fetch stub that never settles on its own: the test decides when each
// upload completes, which is how concurrency is observed at all.
function pending_fetch() {
  var calls = [];
  var impl = function (url) {
    var settle;
    var promise = new Promise(function (resolve) {
      settle = resolve;
    });
    calls.push({url: url, settle: settle});
    return promise;
  };
  impl.calls = calls;
  return impl;
}

// Collects timers instead of running them, so the 429 back-off is stepped
// by the test rather than waited on.
function fake_timers() {
  var pending = [];
  return {
    set: function (fn, ms) {
      var entry = {fn: fn, ms: ms, cancelled: false};
      pending.push(entry);
      return entry;
    },
    clear: function (entry) {
      if (entry) {
        entry.cancelled = true;
      }
    },
    // Fires every timer set for `ms`, which is how the back-off is
    // distinguished from finish_row's fade-out timer.
    run: function (ms) {
      var due = pending.filter(function (e) {
        return e.ms === ms && !e.cancelled;
      });
      pending = pending.filter(function (e) {
        return due.indexOf(e) === -1;
      });
      due.forEach(function (e) {
        e.fn();
      });
      return due.length;
    }
  };
}

function busy_response() {
  return {
    ok: false,
    status: 429,
    json: function () {
      return Promise.resolve({status: 'Too many transfers in progress.'});
    }
  };
}

function ok_response(bytes) {
  return {
    ok: true,
    status: 200,
    json: function () {
      return Promise.resolve({bytes: bytes});
    }
  };
}

function files(n) {
  var out = [];
  for (var i = 0; i < n; i++) {
    out.push({name: 'photo' + i + '.jpg'});
  }
  return out;
}

test('a drop of eight files uploads only three at a time', async function () {
  // The reported bug: eight photos dropped at once, five refused with 429
  // because the server caps a session at three concurrent transfers.
  var fetch_impl = pending_fetch();
  var ui = load_ui(fetch_impl);
  ui.set_cwd('tab1', '/srv/photos');
  ui.start_drop('tab1', 'worker1', files(8));

  assert.strictEqual(fetch_impl.calls.length, 3);

  // Finishing one upload admits exactly one more, never the whole backlog.
  fetch_impl.calls[0].settle(ok_response(10));
  await new Promise(function (r) {
    setImmediate(r);
  });
  assert.strictEqual(fetch_impl.calls.length, 4);

  var seen = 3;
  while (seen < 8) {
    fetch_impl.calls[seen - 3 + 1].settle(ok_response(10));
    /* eslint-disable no-await-in-loop */
    await new Promise(function (r) {
      setImmediate(r);
    });
    seen = fetch_impl.calls.length;
  }

  // All eight were eventually sent, each to the confirmed directory.
  assert.strictEqual(fetch_impl.calls.length, 8);
  assert.ok(fetch_impl.calls[7].url.indexOf('path=%2Fsrv%2Fphotos%2Fphoto7.jpg') !== -1);
});

test('queued uploads are not sent against a closed session', async function () {
  var fetch_impl = pending_fetch();
  var ui = load_ui(fetch_impl);
  ui.set_cwd('tab1', '/srv/photos');
  ui.start_drop('tab1', 'worker1', files(8));
  assert.strictEqual(fetch_impl.calls.length, 3);

  ui.cancel_for_tab('tab1');
  fetch_impl.calls[0].settle(ok_response(10));
  await new Promise(function (r) {
    setImmediate(r);
  });

  assert.strictEqual(fetch_impl.calls.length, 3);
});

test('a 429 frees the slot for the next queued file straight away', async function () {
  var fetch_impl = pending_fetch();
  var timers = fake_timers();
  var ui = load_ui(fetch_impl, timers);
  ui.set_cwd('tab1', '/srv/photos');
  ui.start_drop('tab1', 'worker1', files(5));
  assert.strictEqual(fetch_impl.calls.length, 3);

  // The server is busy with transfers this queue does not schedule (a
  // download, say). The refused upload must not keep holding its slot.
  fetch_impl.calls[0].settle(busy_response());
  await new Promise(function (r) {
    setImmediate(r);
  });
  assert.strictEqual(fetch_impl.calls.length, 4);
});

test('a 429 rejoins the queue instead of failing the file', async function () {
  var fetch_impl = pending_fetch();
  var timers = fake_timers();
  var ui = load_ui(fetch_impl, timers);
  ui.set_cwd('tab1', '/srv/photos');
  ui.start_drop('tab1', 'worker1', files(1));
  assert.strictEqual(fetch_impl.calls.length, 1);

  fetch_impl.calls[0].settle(busy_response());
  await new Promise(function (r) {
    setImmediate(r);
  });
  // Nothing re-sent yet: it is waiting out the back-off, not spinning.
  assert.strictEqual(fetch_impl.calls.length, 1);

  assert.strictEqual(timers.run(1000), 1);
  await new Promise(function (r) {
    setImmediate(r);
  });
  assert.strictEqual(fetch_impl.calls.length, 2);
  assert.strictEqual(
    fetch_impl.calls[1].url,
    fetch_impl.calls[0].url,
    'the retry targets the same destination'
  );

  // And it keeps waiting for as long as the server stays busy, rather than
  // spending a fixed number of tries and giving up.
  var round;
  for (round = 0; round < 20; round++) {
    fetch_impl.calls[fetch_impl.calls.length - 1].settle(busy_response());
    /* eslint-disable no-await-in-loop */
    await new Promise(function (r) {
      setImmediate(r);
    });
    timers.run(1000);
    await new Promise(function (r) {
      setImmediate(r);
    });
  }
  assert.strictEqual(fetch_impl.calls.length, 22);

  fetch_impl.calls[21].settle(ok_response(10));
  await new Promise(function (r) {
    setImmediate(r);
  });
  assert.strictEqual(fetch_impl.calls.length, 22);
});

test('closing the tab stops an upload waiting out a 429', async function () {
  var fetch_impl = pending_fetch();
  var timers = fake_timers();
  var ui = load_ui(fetch_impl, timers);
  ui.set_cwd('tab1', '/srv/photos');
  ui.start_drop('tab1', 'worker1', files(1));

  fetch_impl.calls[0].settle(busy_response());
  await new Promise(function (r) {
    setImmediate(r);
  });

  // Between the 429 and its return to the queue this transfer is in neither
  // `active` nor the queue, so it has to be cancelled on its own.
  ui.cancel_for_tab('tab1');
  timers.run(1000);
  await new Promise(function (r) {
    setImmediate(r);
  });
  assert.strictEqual(fetch_impl.calls.length, 1);
});
