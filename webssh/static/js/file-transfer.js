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

  function upload_url(id, path, filename, overwrite) {
    var url = '/transfer/upload?id=' + encodeURIComponent(id) +
      '&path=' + encodeURIComponent(path) +
      '&filename=' + encodeURIComponent(filename);
    if (overwrite) {
      url = url + '&overwrite=true';
    }
    return url;
  }

  function download_url(id, path) {
    return '/transfer/download?id=' + encodeURIComponent(id) +
      '&path=' + encodeURIComponent(path);
  }

  return {
    parse_osc7: parse_osc7,
    resolve_path: resolve_path,
    format_bytes: format_bytes,
    upload_url: upload_url,
    download_url: download_url
  };
}());

if (typeof module !== 'undefined' && module.exports) {
  module.exports = webssh_transfer;
}
