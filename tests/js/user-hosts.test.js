'use strict';

var test = require('node:test');
var assert = require('node:assert');
var hosts = require('../../webssh/static/js/user-hosts.js');

test('validate_port omits a blank port so the server default applies', function () {
  assert.deepStrictEqual(hosts.validate_port(''), {omit: true});
  assert.deepStrictEqual(hosts.validate_port('   '), {omit: true});
});

test('validate_port accepts values in range', function () {
  assert.deepStrictEqual(hosts.validate_port('22'), {port: 22});
  assert.deepStrictEqual(hosts.validate_port('2222'), {port: 2222});
  assert.deepStrictEqual(hosts.validate_port('65535'), {port: 65535});
  assert.deepStrictEqual(hosts.validate_port('1'), {port: 1});
});

test('validate_port rejects out-of-range values instead of rewriting them', function () {
  // Regression: a typo was once silently clamped to 22, routing around the
  // server-side 1-65535 check and connecting the user to a port they did
  // not type.
  assert.deepStrictEqual(hosts.validate_port('0'), {invalid: true});
  assert.deepStrictEqual(hosts.validate_port('-5'), {invalid: true});
  assert.deepStrictEqual(hosts.validate_port('99999'), {invalid: true});
  assert.deepStrictEqual(hosts.validate_port('65536'), {invalid: true});
});

test('validate_port rejects non-numeric text', function () {
  assert.deepStrictEqual(hosts.validate_port('abc'), {invalid: true});
});

test('validate_port preserves parseInt leniency for a numeric prefix', function () {
  // Deliberate: the original inline logic accepted this, and the
  // extraction must not tighten behaviour. Not a bug to "fix".
  assert.deepStrictEqual(hosts.validate_port('22abc'), {port: 22});
});

function row(over) {
  var base = {name: '', hostname: '', port_text: '', keys_text: '',
              username: '', default_command: ''};
  for (var k in over) { base[k] = over[k]; }
  return base;
}

test('build_host_payload maps a full row and trims every field', function () {
  var out = hosts.build_host_payload([row({
    name: '  homelab ', hostname: ' nas.lan ', port_text: '2222',
    keys_text: ' ssh-ed25519 AAAA ', username: ' ryan ',
    default_command: ' tmux attach '
  })]);
  assert.strictEqual(out.error, null);
  assert.deepStrictEqual(out.hosts, [{
    name: 'homelab', hostname: 'nas.lan', host_key: ['ssh-ed25519 AAAA'],
    username: 'ryan', default_command: 'tmux attach', port: 2222
  }]);
});

test('build_host_payload emits host_key singular, never host_keys', function () {
  // The server consumes host_key and returns host_keys. Sending the wrong
  // one silently drops the user's pinned keys, which downgrades the host to
  // the global policy.
  var out = hosts.build_host_payload([row({
    hostname: 'a.com', keys_text: 'ssh-ed25519 AAAA'
  })]);
  assert.ok('host_key' in out.hosts[0]);
  assert.ok(!('host_keys' in out.hosts[0]));
});

test('build_host_payload splits multiple keys and drops blank lines', function () {
  var out = hosts.build_host_payload([row({
    hostname: 'a.com', keys_text: 'ssh-ed25519 AAA\n\n  \nssh-rsa BBB\n'
  })]);
  assert.deepStrictEqual(out.hosts[0].host_key, ['ssh-ed25519 AAA', 'ssh-rsa BBB']);
});

test('build_host_payload defaults an empty name to the hostname', function () {
  var out = hosts.build_host_payload([row({hostname: 'nas.lan'})]);
  assert.strictEqual(out.hosts[0].name, 'nas.lan');
});

test('build_host_payload omits port entirely when blank', function () {
  var out = hosts.build_host_payload([row({hostname: 'a.com'})]);
  assert.ok(!('port' in out.hosts[0]),
            'a blank port must be absent, not null/0/NaN, so the server defaults it');
});

test('build_host_payload skips rows with a blank hostname', function () {
  var out = hosts.build_host_payload([
    row({hostname: 'a.com'}),
    row({name: 'half-filled', keys_text: 'ssh-ed25519 AAA'}),
    row({hostname: 'b.com'})
  ]);
  assert.strictEqual(out.hosts.length, 2);
  assert.deepStrictEqual([out.hosts[0].hostname, out.hosts[1].hostname],
                         ['a.com', 'b.com']);
});

test('build_host_payload reports an invalid port with the offending row index', function () {
  var out = hosts.build_host_payload([
    row({hostname: 'a.com'}),
    row({name: 'db', hostname: 'b.com', port_text: '99999'})
  ]);
  assert.strictEqual(out.error,
    'Invalid port "99999" for host "db" (must be 1-65535).');
  assert.strictEqual(out.error_index, 1);
});

test('build_host_payload stops at the first invalid row', function () {
  var out = hosts.build_host_payload([
    row({hostname: 'a.com', port_text: '0'}),
    row({hostname: 'b.com', port_text: '70000'})
  ]);
  assert.strictEqual(out.error_index, 0);
});

test('build_host_payload keeps hosts collected before an invalid row', function () {
  // Matches the original inline behaviour. Deliberately NOT an empty
  // list: PUT /api/hosts treats an explicit empty list as "clear my
  // hosts", so a caller that read .hosts while ignoring .error would
  // wipe the user's saved hosts.
  var out = hosts.build_host_payload([
    row({hostname: 'good.lan'}),
    row({hostname: 'bad.lan', port_text: '99999'})
  ]);
  assert.strictEqual(out.error_index, 1);
  assert.strictEqual(out.hosts.length, 1);
  assert.strictEqual(out.hosts[0].hostname, 'good.lan');
});

test('build_host_payload returns an empty list for no rows', function () {
  // An explicit empty list is a legitimate "clear my hosts", distinct from
  // a failure, and the server honours it as such.
  assert.deepStrictEqual(hosts.build_host_payload([]),
                         {hosts: [], error: null, error_index: -1});
});

function ui(over) {
  var base = {font_size_text: '', background: '', foreground: '', cursor: '',
              encoding: '', term: '', cursor_blink: true, key_source: 'upload'};
  for (var k in over) { base[k] = over[k]; }
  return base;
}

test('merge_settings carries roamed last-used values forward', function () {
  // Regression: the pane only knows appearance keys, and the settings PUT
  // replaces the whole blob, so every save used to wipe the roamed values.
  // That is invisible on one machine because localStorage covers it, and
  // only shows up on a second machine -- which is the point of roaming.
  var current = {last_hostname: 'nas.lan', last_username: 'ryan', last_port: 2222};
  var out = hosts.merge_settings(current, ui({font_size_text: '16'}));
  assert.strictEqual(out.last_hostname, 'nas.lan');
  assert.strictEqual(out.last_username, 'ryan');
  assert.strictEqual(out.last_port, 2222);
  assert.strictEqual(out.font_size, 16);
});

test('merge_settings omits roaming keys absent from current settings', function () {
  var out = hosts.merge_settings({}, ui({font_size_text: '16'}));
  assert.ok(!('last_hostname' in out),
            'absent keys must be omitted, not sent as null/undefined');
  assert.ok(!('last_port' in out));
});

test('merge_settings carries only the three known roaming keys', function () {
  var out = hosts.merge_settings(
    {last_hostname: 'a', nonsense: 'x', credential: 'secret'}, ui({}));
  assert.strictEqual(out.last_hostname, 'a');
  assert.ok(!('nonsense' in out));
  assert.ok(!('credential' in out));
});

test('merge_settings includes appearance values only when non-empty', function () {
  var out = hosts.merge_settings({}, ui({background: ' black ', foreground: ''}));
  assert.strictEqual(out.background, 'black');
  assert.ok(!('foreground' in out));
});

test('merge_settings omits a non-positive font size', function () {
  assert.ok(!('font_size' in hosts.merge_settings({}, ui({font_size_text: ''}))));
  assert.ok(!('font_size' in hosts.merge_settings({}, ui({font_size_text: '0'}))));
  assert.ok(!('font_size' in hosts.merge_settings({}, ui({font_size_text: 'abc'}))));
});

test('merge_settings always includes cursor_blink and key_source', function () {
  var out = hosts.merge_settings({}, ui({cursor_blink: false, key_source: 'stored'}));
  assert.strictEqual(out.cursor_blink, false);
  assert.strictEqual(out.key_source, 'stored');
});

test('roaming_update maps only the three roaming form fields', function () {
  assert.deepStrictEqual(hosts.roaming_update('hostname', 'nas.lan'),
                         {key: 'last_hostname', value: 'nas.lan'});
  assert.deepStrictEqual(hosts.roaming_update('username', 'ryan'),
                         {key: 'last_username', value: 'ryan'});
  assert.strictEqual(hosts.roaming_update('credential', 'hunter2'), null);
  assert.strictEqual(hosts.roaming_update('totp', '123456'), null);
  assert.strictEqual(hosts.roaming_update('passphrase', 'x'), null);
});

test('roaming_update coerces port to an integer', function () {
  // The server validates last_port as an int 1-65535; a string would be
  // rejected with a 400 the user never sees.
  assert.deepStrictEqual(hosts.roaming_update('port', '2222'),
                         {key: 'last_port', value: 2222});
  assert.strictEqual(typeof hosts.roaming_update('port', '2222').value, 'number');
});

test('roaming_update drops an unusable port instead of sending it', function () {
  assert.strictEqual(hosts.roaming_update('port', 'abc'), null);
  assert.strictEqual(hosts.roaming_update('port', '0'), null);
});

test('resolve_terminal_options lets a URL parameter beat a stored value', function () {
  // Existing shared links carry ?fontsize= and ?bgcolor=; a stored
  // preference must never override an explicit URL parameter.
  var out = hosts.resolve_terminal_options(
    {fontsize: '20', bgcolor: 'navy'},
    {font_size: 19, background: 'black'});
  assert.strictEqual(out.fontSize, 20);
  assert.strictEqual(out.theme.background, 'navy');
});

test('resolve_terminal_options falls back to stored values', function () {
  var out = hosts.resolve_terminal_options({}, {font_size: 19, background: 'black'});
  assert.strictEqual(out.fontSize, 19);
  assert.strictEqual(out.theme.background, 'black');
});

test('resolve_terminal_options falls back to built-in defaults', function () {
  var out = hosts.resolve_terminal_options({}, {});
  assert.strictEqual(out.theme.background, 'black');
  assert.strictEqual(out.theme.foreground, 'white');
  assert.strictEqual(out.theme.cursor, 'white');
  assert.strictEqual(out.cursorBlink, true);
});

test('resolve_terminal_options omits fontSize when nothing resolves', function () {
  assert.ok(!('fontSize' in hosts.resolve_terminal_options({}, {})));
});

test('resolve_terminal_options ignores a malformed font size', function () {
  // A bad stored value must not break the terminal.
  assert.ok(!('fontSize' in hosts.resolve_terminal_options({fontsize: 'abc'}, {})));
});

test('resolve_terminal_options honours cursor_blink false', function () {
  assert.strictEqual(
    hosts.resolve_terminal_options({}, {cursor_blink: false}).cursorBlink, false);
});

test('resolve_terminal_options falls back through fontcolor for the cursor', function () {
  var out = hosts.resolve_terminal_options({fontcolor: 'lime'}, {});
  assert.strictEqual(out.theme.cursor, 'lime');
});

test('resolve_terminal_options prefers a URL cursor over a stored cursor', function () {
  var out = hosts.resolve_terminal_options(
    {cursor: 'red'}, {cursor: 'blue', foreground: 'green'});
  assert.strictEqual(out.theme.cursor, 'red');
});

test('resolve_terminal_options prefers a stored cursor over URL fontcolor', function () {
  // The chain is url cursor -> stored cursor -> url fontcolor ->
  // stored foreground -> 'white'. The ordering looks arbitrary but is
  // deliberate: an explicitly chosen cursor colour, from either source,
  // outranks a foreground colour being reused as a fallback.
  var out = hosts.resolve_terminal_options(
    {fontcolor: 'lime'}, {cursor: 'blue'});
  assert.strictEqual(out.theme.cursor, 'blue');
});

test('save_error_text surfaces the server message on 400', function () {
  assert.strictEqual(
    hosts.save_error_text(400, {error: 'Invalid port "99999" for host "db".'}),
    'Invalid port "99999" for host "db".');
});

test('save_error_text falls back to a generic message on a bodyless 400', function () {
  assert.strictEqual(hosts.save_error_text(400, null),
                     'Rejected: check hostnames, ports, and host keys.');
});

test('save_error_text never surfaces server detail on 500', function () {
  // Server-state messages can embed filesystem paths. The server already
  // genericises them; the client must not undo that by echoing a body.
  assert.strictEqual(
    hosts.save_error_text(500, {error: '/var/lib/webssh/user-data denied'}),
    'Save failed.');
});

test('parse_command_key reads a legacy command key', function () {
  assert.deepStrictEqual(hosts.parse_command_key('command:nas.lan:2222'),
                         {hostname: 'nas.lan', port: 2222});
});

test('parse_command_key defaults a missing port to 22', function () {
  assert.deepStrictEqual(hosts.parse_command_key('command:nas.lan:'),
                         {hostname: 'nas.lan', port: 22});
});

test('parse_command_key ignores unrelated localStorage keys', function () {
  assert.strictEqual(hosts.parse_command_key('hostname'), null);
  assert.strictEqual(hosts.parse_command_key('webssh_migrated_commands'), null);
  assert.strictEqual(hosts.parse_command_key(''), null);
  assert.strictEqual(hosts.parse_command_key(null), null);
});

test('merge_migrated_commands preserves every field of every host', function () {
  // This payload replaces the user's whole host list. A dropped field here
  // silently destroys pinned host keys.
  var stored = [{
    name: 'homelab', hostname: 'nas.lan', port: 2222,
    host_keys: ['ssh-ed25519 AAA'], username: 'ryan', default_command: ''
  }];
  var out = hosts.merge_migrated_commands(
    stored, [{hostname: 'nas.lan', port: 2222, command: 'tmux attach'}]);
  assert.strictEqual(out.changed, true);
  assert.deepStrictEqual(out.payload, [{
    name: 'homelab', hostname: 'nas.lan', port: 2222,
    host_key: ['ssh-ed25519 AAA'], username: 'ryan',
    default_command: 'tmux attach'
  }]);
});

test('merge_migrated_commands converts host_keys to host_key', function () {
  var out = hosts.merge_migrated_commands(
    [{name: 'a', hostname: 'a.com', port: 22, host_keys: ['ssh-rsa AAA'],
      username: '', default_command: ''}],
    [{hostname: 'a.com', port: 22, command: 'htop'}]);
  assert.deepStrictEqual(out.payload[0].host_key, ['ssh-rsa AAA']);
  assert.ok(!('host_keys' in out.payload[0]));
});

test('merge_migrated_commands carries through hosts it does not migrate', function () {
  var stored = [
    {name: 'a', hostname: 'a.com', port: 22, host_keys: [], username: '',
     default_command: ''},
    {name: 'b', hostname: 'b.com', port: 22, host_keys: ['ssh-rsa BBB'],
     username: 'bob', default_command: 'top'}
  ];
  var out = hosts.merge_migrated_commands(
    stored, [{hostname: 'a.com', port: 22, command: 'htop'}]);
  assert.strictEqual(out.payload.length, 2);
  assert.deepStrictEqual(out.payload[1], {
    name: 'b', hostname: 'b.com', port: 22, host_key: ['ssh-rsa BBB'],
    username: 'bob', default_command: 'top'
  });
});

test('merge_migrated_commands never invents a host', function () {
  var out = hosts.merge_migrated_commands(
    [], [{hostname: 'ghost.lan', port: 22, command: 'htop'}]);
  assert.strictEqual(out.changed, false);
  assert.deepStrictEqual(out.payload, []);
});

test('merge_migrated_commands does not overwrite an existing command', function () {
  var out = hosts.merge_migrated_commands(
    [{name: 'a', hostname: 'a.com', port: 22, host_keys: [], username: '',
      default_command: 'already set'}],
    [{hostname: 'a.com', port: 22, command: 'from localStorage'}]);
  assert.strictEqual(out.changed, false);
});

test('merge_migrated_commands reports no change when nothing matches', function () {
  var out = hosts.merge_migrated_commands(
    [{name: 'a', hostname: 'a.com', port: 22, host_keys: [], username: '',
      default_command: ''}],
    [{hostname: 'other.lan', port: 22, command: 'htop'}]);
  assert.strictEqual(out.changed, false);
  assert.deepStrictEqual(out.payload, []);
});

var SECRETS = ['credential', 'totp', 'password', 'passphrase', 'privatekey'];

function assert_no_secrets(label, value) {
  var text = JSON.stringify(value);
  for (var i = 0; i < SECRETS.length; i++) {
    assert.ok(text.indexOf(SECRETS[i]) === -1,
              label + ' must never carry ' + SECRETS[i] + ', got: ' + text);
  }
}

test('no builder output can carry a secret field', function () {
  // The server whitelists keys as a backstop, but a client-side leak would
  // still transmit the secret over the wire and log it on a validation error.
  var poisoned = {
    name: 'a', hostname: 'a.com', port_text: '22', keys_text: '',
    username: 'u', default_command: 'cmd',
    credential: 'hunter2', totp: '123456', password: 'p',
    passphrase: 'pp', privatekey: 'pk'
  };
  assert_no_secrets('build_host_payload',
                    hosts.build_host_payload([poisoned]).hosts);

  var poisoned_current = {
    last_hostname: 'nas.lan', credential: 'hunter2', totp: '123456',
    password: 'p', passphrase: 'pp', privatekey: 'pk'
  };
  var poisoned_ui = {
    font_size_text: '14', background: '', foreground: '', cursor: '',
    encoding: '', term: '', cursor_blink: true, key_source: 'upload',
    credential: 'hunter2', totp: '123456'
  };
  assert_no_secrets('merge_settings',
                    hosts.merge_settings(poisoned_current, poisoned_ui));

  assert_no_secrets('merge_migrated_commands', hosts.merge_migrated_commands(
    [{name: 'a', hostname: 'a.com', port: 22, host_keys: [], username: '',
      default_command: '', credential: 'hunter2', totp: '123456'}],
    [{hostname: 'a.com', port: 22, command: 'htop'}]).payload);
});

test('roaming_update refuses every secret-bearing form field', function () {
  for (var i = 0; i < SECRETS.length; i++) {
    assert.strictEqual(hosts.roaming_update(SECRETS[i], 'leaked'), null,
                       SECRETS[i] + ' must not roam');
  }
});
