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
    match_entry: match_entry,
    format_bytes: format_bytes,
    upload_url: upload_url,
    download_url: download_url
  };
}());

if (typeof module !== 'undefined' && module.exports) {
  module.exports = webssh_transfer;
}
