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

test('build_host_payload returns an empty list for no rows', function () {
  // An explicit empty list is a legitimate "clear my hosts", distinct from
  // a failure, and the server honours it as such.
  assert.deepStrictEqual(hosts.build_host_payload([]),
                         {hosts: [], error: null, error_index: -1});
});
