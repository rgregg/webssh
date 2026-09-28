/*jslint browser:true */
/*
 * Pure decision logic for browser/host file transfer.
 *
 * No DOM access and no jQuery, so this file is unit-testable under
 * `node --test` with no browser and no packages. transfer-ui.js does the
 * DOM work and calls in here for decisions.
 */

var webssh_transfer = (function () {
  'use strict';

  // Parses the payload of an OSC 7 sequence, which shells emit as
  // file://<host>/<path> to report their working directory. Returns null
  // for anything unrecognised so the caller keeps its last known good
  // directory rather than retargeting uploads at a bogus path.
  function parse_osc7(payload) {
    var text = (payload === undefined || payload === null) ? '' : String(payload);
    if (text.indexOf('file://') !== 0) {
      return null;
    }
    var rest = text.slice(7);
    var slash = rest.indexOf('/');
    if (slash === -1) {
      return null;
    }
    var raw = rest.slice(slash);
    if (!raw) {
      return null;
    }
    try {
      return decodeURIComponent(raw);
    } catch (e) {
      // Malformed percent escape. Treat as unknown rather than throwing
      // inside the terminal's parser callback.
      return null;
    }
  }

  function resolve_path(cwd, input) {
    var name = (input === undefined || input === null) ? '' : String(input);
    if (name.charAt(0) === '/') {
      return name;
    }
    var dir = (cwd === undefined || cwd === null) ? '' : String(cwd);
    if (!dir) {
      return name;
    }
    if (dir.charAt(dir.length - 1) === '/') {
      return dir + name;
    }
    return dir + '/' + name;
  }

  var UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

  function format_bytes(n) {
    var value = Number(n) || 0;
    var unit = 0;
    while (value >= 1024 && unit < UNITS.length - 1) {
      value = value / 1024;
      unit = unit + 1;
    }
    if (unit === 0) {
      return String(Math.round(value)) + ' B';
    }
    return value.toFixed(1) + ' ' + UNITS[unit];
  }

  // Neither builder takes a worker id: the token travels in the
  // X-Worker-Id header for upload, and the download is authorised by a
  // single-use ticket instead.
  function upload_url(path, filename, overwrite) {
    var url = '/transfer/upload?path=' + encodeURIComponent(path) +
      '&filename=' + encodeURIComponent(filename);
    if (overwrite) {
      url = url + '&overwrite=true';
    }
    return url;
  }

  function download_url(ticket) {
    return '/transfer/download?ticket=' + encodeURIComponent(ticket);
  }

  // Splits what the user typed into the directory to list and the fragment
  // to filter by. dir === null means "no directory was typed, keep whatever
  // is currently listed" -- the caller owns that state, so this stays free
  // of UI knowledge.
  function split_path(input) {
    var text = (input === undefined || input === null) ? '' : String(input);
    var cut = text.lastIndexOf('/');
    if (cut === -1) {
      return {dir: null, filter: text};
    }
    // Everything up to the last slash is the directory. For a path directly
    // under root that slice is empty, which would reach the server as a
    // relative listing of the home directory, so keep the slash.
    var dir = text.slice(0, cut);
    return {dir: dir === '' ? '/' : dir, filter: text.slice(cut + 1)};
  }

  // The directory above an absolute path, or null at the root -- and for
  // anything not absolute, whose parent cannot be known here.
  function parent_dir(path) {
    var text = (path === undefined || path === null) ? '' : String(path);
    if (text.charAt(0) !== '/') {
      return null;
    }
    var trimmed = text.replace(/\/+$/, '');
    if (!trimmed) {
      return null;
    }
    var cut = trimmed.lastIndexOf('/');
    return cut === 0 ? '/' : trimmed.slice(0, cut);
  }

  // Where a transfer dialog opens. Both inputs are {dir, at} or null: the
  // directory the shell last reported, and the one last browsed to in this
  // dialog. The more recent is the better guess at where the user is --
  // a shell that stopped reporting (tmux, screen) leaves a stale cwd that
  // the last browse outdates, and a shell that reports at every prompt
  // outdates the last browse as soon as the user runs a command. '.' is
  // the SFTP home, for when neither is known.
  function choose_start_dir(cwd, last) {
    if (cwd && last) {
      return last.at > cwd.at ? last.dir : cwd.dir;
    }
    if (last) {
      return last.dir;
    }
    if (cwd) {
      return cwd.dir;
    }
    return '.';
  }

  // Per-host memory of the last folder each dialog was in. Hosts differ in
  // layout, so memory is keyed by connection; download and upload are kept
  // apart, since where files come from and where they go often differ.
  var MAX_REMEMBERED_HOSTS = 50;

  function host_key(username, hostname, port) {
    return String(username) + '@' + String(hostname).toLowerCase() + ':' +
      String(port || 22);
  }

  function valid_entry(entry) {
    return !!entry && typeof entry === 'object' &&
      typeof entry.dir === 'string' && typeof entry.at === 'number';
  }

  function recall_dir(store, host, kind) {
    if (!store || typeof store !== 'object') {
      return null;
    }
    var slot = store[host];
    if (!slot || typeof slot !== 'object' || !valid_entry(slot[kind])) {
      return null;
    }
    return {dir: slot[kind].dir, at: slot[kind].at};
  }

  function newest(slot) {
    var at = -Infinity;
    for (var kind in slot) {
      if (Object.prototype.hasOwnProperty.call(slot, kind) &&
          valid_entry(slot[kind]) && slot[kind].at > at) {
        at = slot[kind].at;
      }
    }
    return at;
  }

  // Returns a new store; the caller persists it. Past the cap, the host
  // used least recently is forgotten, so the store cannot grow unbounded.
  function remember_dir(store, host, kind, dir, now) {
    var out = {};
    var source = (store && typeof store === 'object') ? store : {};
    var name;
    for (name in source) {
      if (Object.prototype.hasOwnProperty.call(source, name) &&
          source[name] && typeof source[name] === 'object') {
        out[name] = source[name];
      }
    }
    var slot = {};
    for (name in out[host] || {}) {
      if (Object.prototype.hasOwnProperty.call(out[host], name)) {
        slot[name] = out[host][name];
      }
    }
    slot[kind] = {dir: dir, at: now};
    out[host] = slot;

    var hosts = Object.keys(out);
    while (hosts.length > MAX_REMEMBERED_HOSTS) {
      var oldest = hosts[0];
      for (var i = 1; i < hosts.length; i++) {
        if (newest(out[hosts[i]]) < newest(out[oldest])) {
          oldest = hosts[i];
        }
      }
      delete out[oldest];
      hosts = Object.keys(out);
    }
    return out;
  }

  function match_entry(name, filter) {
    var needle = (filter === undefined || filter === null)
      ? '' : String(filter).trim();
    if (!needle) {
      return true;
    }
    return String(name).toLowerCase().indexOf(needle.toLowerCase()) !== -1;
  }

  // Destinations for one drop, all under the directory the user confirmed.
  // Kept here rather than in the drop handler so the batch behaviour is
  // testable without a DOM: an absolute name still wins, and an unknown
  // directory leaves the name relative for the server to resolve against
  // the SFTP home.
  function resolve_upload_paths(dir, names) {
    var out = [];
    var list = names || [];
    for (var i = 0; i < list.length; i++) {
      out.push(resolve_path(dir, list[i]));
    }
    return out;
  }

  // What the uploader dialog says it is about to send. A single file is
  // named outright -- that is the case where the name is the thing worth
  // checking before you commit to a destination -- and a batch is counted.
  function describe_selection(names) {
    var list = names || [];
    if (!list.length) {
      return 'No files selected';
    }
    if (list.length === 1) {
      return String(list[0]);
    }
    return list.length + ' files selected';
  }

  // A fixed-concurrency job queue. The server caps a session at
  // MAX_CONCURRENT_TRANSFERS (3) and answers anything beyond it with 429,
  // so dropping eight photos used to upload three and fail five. Holding
  // the extras here instead means the drop simply takes longer.
  //
  // A job is `run(done)`; it must call `done` exactly once when it settles.
  // A double `done` is ignored rather than freeing two slots, since that
  // would push a job past the very cap this exists to respect.
  function make_queue(limit) {
    var running = 0;
    var pending = [];

    function pump() {
      while (running < limit && pending.length) {
        var job = pending.shift();
        if (job.cancelled) {
          continue;
        }
        job.started = true;
        running = running + 1;
        try {
          job.run(release(job));
        } catch (err) {
          // A job that throws before it can call done would hold its slot
          // for the life of the queue. Free it, then let the error out as
          // it would have without this guard.
          release(job)();
          throw err;
        }
      }
    }

    function release(job) {
      return function () {
        if (job.settled) {
          return;
        }
        job.settled = true;
        running = running - 1;
        pump();
      };
    }

    return {
      push: function (run, on_cancel) {
        var job = {
          run: run,
          on_cancel: on_cancel,
          cancelled: false,
          started: false,
          settled: false
        };
        pending.push(job);
        pump();
        return job;
      },
      // Only a job still waiting can be cancelled here; one already running
      // owns an AbortController and is cancelled through that instead.
      cancel: function (job) {
        if (!job || job.cancelled || job.started) {
          return false;
        }
        job.cancelled = true;
        var at = pending.indexOf(job);
        if (at !== -1) {
          pending.splice(at, 1);
        }
        if (job.on_cancel) {
          job.on_cancel();
        }
        return true;
      },
      clear: function () {
        var waiting = pending;
        pending = [];
        for (var i = 0; i < waiting.length; i++) {
          waiting[i].cancelled = true;
          if (waiting[i].on_cancel) {
            waiting[i].on_cancel();
          }
        }
      },
      pending: function () {
        return pending.length;
      },
      running: function () {
        return running;
      }
    };
  }

  return {
    parse_osc7: parse_osc7,
    resolve_path: resolve_path,
    resolve_upload_paths: resolve_upload_paths,
    make_queue: make_queue,
    split_path: split_path,
    parent_dir: parent_dir,
    choose_start_dir: choose_start_dir,
    host_key: host_key,
    recall_dir: recall_dir,
    remember_dir: remember_dir,
    MAX_REMEMBERED_HOSTS: MAX_REMEMBERED_HOSTS,
    match_entry: match_entry,
    describe_selection: describe_selection,
    format_bytes: format_bytes,
    upload_url: upload_url,
    download_url: download_url
  };
}());

if (typeof module !== 'undefined' && module.exports) {
  module.exports = webssh_transfer;
}
