/*jslint browser:true */
/*
 * Pure decision logic for the user-managed hosts and settings feature.
 *
 * This module holds no DOM access and no jQuery dependency: main.js reads
 * the settings pane into plain values and passes them here. That keeps this
 * file unit-testable under `node --test` with no browser and no packages.
 */

var webssh_hosts = (function () {
  'use strict';

  // Returns exactly one of {omit: true}, {port: n}, or {invalid: true}.
  // A blank port is omitted rather than defaulted here, so the server
  // applies its own documented default; a typed value is never rewritten.
  function validate_port(text) {
    var trimmed = (text === undefined || text === null) ? '' : String(text).trim();
    if (!trimmed) {
      return {omit: true};
    }
    var port = parseInt(trimmed, 10);
    if (!(port > 0 && port <= 65535)) {
      return {invalid: true};
    }
    return {port: port};
  }

  return {
    validate_port: validate_port
  };
}());

if (typeof module !== 'undefined' && module.exports) {
  module.exports = webssh_hosts;
}
