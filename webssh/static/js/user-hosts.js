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
        // Preserve hosts collected before this row, matching the original
        // inline behaviour. Returning [] here looks tidy but is a trap:
        // PUT /api/hosts treats an explicit empty list as "clear my hosts",
        // so a caller that reads .hosts without checking .error would wipe
        // the user's saved hosts and pinned keys.
        return {
          hosts: result,
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

  // Form field name -> stored settings key. These three are the ONLY fields
  // that roam. Everything else in the form, including credential and totp,
  // is deliberately absent so secrets cannot reach the server structurally.
  var ROAMING_FIELDS = {
    hostname: 'last_hostname',
    username: 'last_username',
    port: 'last_port'
  };

  var APPEARANCE_KEYS = ['background', 'foreground', 'cursor', 'encoding', 'term'];

  function merge_settings(current, ui) {
    var settings = {};
    var size = parseInt(ui.font_size_text, 10);
    if (size > 0) {
      settings.font_size = size;
    }
    for (var i = 0; i < APPEARANCE_KEYS.length; i++) {
      var key = APPEARANCE_KEYS[i];
      var value = trimmed(ui[key]);
      if (value) {
        settings[key] = value;
      }
    }
    settings.cursor_blink = ui.cursor_blink;
    settings.key_source = ui.key_source;
    // The settings PUT replaces the whole stored blob and this pane only
    // knows appearance keys, so carry the roamed values forward. Only the
    // known keys, to keep the secrets invariant structural.
    for (var name in ROAMING_FIELDS) {
      var roam_key = ROAMING_FIELDS[name];
      if (current[roam_key] !== undefined) {
        settings[roam_key] = current[roam_key];
      }
    }
    return settings;
  }

  function roaming_update(name, value) {
    var roam_key = ROAMING_FIELDS[name];
    if (!roam_key) {
      return null;
    }
    if (name === 'port') {
      var port = parseInt(value, 10);
      if (!(port > 0)) {
        return null;
      }
      return {key: roam_key, value: port};
    }
    return {key: roam_key, value: value};
  }

  // Precedence: URL parameter, then stored preference, then built-in default.
  function resolve_terminal_options(url_opts, stored) {
    var options = {
      cursorBlink: stored.cursor_blink !== false,
      theme: {
        background: url_opts.bgcolor || stored.background || 'black',
        foreground: url_opts.fontcolor || stored.foreground || 'white',
        cursor: url_opts.cursor || stored.cursor ||
                url_opts.fontcolor || stored.foreground || 'white'
      }
    };
    var fontsize = parseInt(url_opts.fontsize || stored.font_size, 10);
    if (fontsize && fontsize > 0) {
      options.fontSize = fontsize;
    }
    return options;
  }

  // A 400 describes the user's own input and is safe to show. Anything else
  // may describe server state, so it gets a fixed generic message.
  function save_error_text(status, body) {
    if (status === 400) {
      if (body && body.error) {
        return body.error;
      }
      return 'Rejected: check hostnames, ports, and host keys.';
    }
    return 'Save failed.';
  }

  // Legacy per-host default commands were stored under 'command:<host>:<port>'.
  function parse_command_key(key) {
    if (!key || String(key).indexOf('command:') !== 0) {
      return null;
    }
    var parts = String(key).split(':');
    return {
      hostname: parts[1],
      port: parseInt(parts[2], 10) || 22
    };
  }

  // Returns the full replacement payload, since PUT /api/hosts replaces the
  // whole list. Every stored field is carried through; only default_command
  // is filled in, and only where the host has none.
  function merge_migrated_commands(stored_hosts, found) {
    var index = {};
    var i;
    for (i = 0; i < stored_hosts.length; i++) {
      index[stored_hosts[i].hostname + ':' + stored_hosts[i].port] = stored_hosts[i];
    }
    var changed = false;
    for (i = 0; i < found.length; i++) {
      var match = index[found[i].hostname + ':' + found[i].port];
      if (match && !match.default_command) {
        match.default_command = found[i].command;
        changed = true;
      }
    }
    if (!changed) {
      return {payload: [], changed: false};
    }
    var payload = [];
    for (i = 0; i < stored_hosts.length; i++) {
      var h = stored_hosts[i];
      payload.push({
        name: h.name,
        hostname: h.hostname,
        port: h.port,
        host_key: h.host_keys || [],
        username: h.username || '',
        default_command: h.default_command || ''
      });
    }
    return {payload: payload, changed: true};
  }

  return {
    validate_port: validate_port,
    build_host_payload: build_host_payload,
    ROAMING_FIELDS: ROAMING_FIELDS,
    merge_settings: merge_settings,
    roaming_update: roaming_update,
    resolve_terminal_options: resolve_terminal_options,
    save_error_text: save_error_text,
    parse_command_key: parse_command_key,
    merge_migrated_commands: merge_migrated_commands
  };
}());

if (typeof module !== 'undefined' && module.exports) {
  module.exports = webssh_hosts;
}
