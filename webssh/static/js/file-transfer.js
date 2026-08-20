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

  return {
    parse_osc7: parse_osc7,
    resolve_path: resolve_path,
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
