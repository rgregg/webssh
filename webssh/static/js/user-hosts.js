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

  function split_keys(text) {
    var raw = (text === undefined || text === null) ? '' : String(text);
    var parts = raw.split('\n');
    var cleaned = [];
    for (var i = 0; i < parts.length; i++) {
      var k = parts[i].trim();
      if (k) {
        cleaned.push(k);
      }
    }
    return cleaned;
  }

  function trimmed(value) {
    return (value === undefined || value === null) ? '' : String(value).trim();
  }

  // rows: [{name, hostname, port_text, keys_text, username, default_command}]
  // Rows with a blank hostname are skipped, matching the pane's behaviour of
  // ignoring a half-filled row rather than submitting it.
  function build_host_payload(rows) {
    var result = [];
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var hostname = trimmed(r.hostname);
      if (!hostname) {
        continue;
      }
      var name = trimmed(r.name) || hostname;
      var host = {
        name: name,
        hostname: hostname,
        host_key: split_keys(r.keys_text),
        username: trimmed(r.username),
        default_command: trimmed(r.default_command)
      };
      var port_result = validate_port(r.port_text);
      if (port_result.invalid) {
        return {
          hosts: [],
          error: 'Invalid port "' + trimmed(r.port_text) +
                 '" for host "' + name + '" (must be 1-65535).',
          error_index: i
        };
      }
      if (port_result.port) {
        host.port = port_result.port;
      }
      result.push(host);
    }
    return {hosts: result, error: null, error_index: -1};
  }

  return {
    validate_port: validate_port,
    build_host_payload: build_host_payload
  };
}());

if (typeof module !== 'undefined' && module.exports) {
  module.exports = webssh_hosts;
}
