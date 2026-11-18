'use strict';

// Tailcat rows in the settings pane and Tailcat values in the connect form.
// The server is the real gate (see tests/test_tailcat.py); these pin down
// what the browser sends, in particular that a saved address is never
// required to be re-sent and that a bad address is never echoed.

var test = require('node:test');
var assert = require('node:assert');
var hosts = require('../../webssh/static/js/user-hosts.js');

var ADDRESS = 'tc' + new Array(41).join('Ab');  // 80 chars, valid alphabet

function row(over) {
  var base = {name: '', hostname: '', port_text: '', keys_text: '',
              username: '', default_command: '', transport: 'tailcat',
              tailcat_address: '', tailcat_identity: false, id: ''};
  for (var k in over) { base[k] = over[k]; }
  return base;
}

test('a new Tailcat row sends its address and no hostname', function () {
  var out = hosts.build_host_payload([row({
    name: ' lab ', tailcat_address: ' ' + ADDRESS + ' ', username: ' ryan ',
    tailcat_identity: true, port_text: '2222'
  })]);
  assert.strictEqual(out.error, null);
  assert.deepStrictEqual(out.hosts, [{
    transport: 'tailcat', name: 'lab', host_key: [], username: 'ryan',
    default_command: '', tailcat_identity: true,
    tailcat_address: ADDRESS, port: 2222
  }]);
});

test('a saved Tailcat row is sent by id, without an address', function () {
  var id = 'u0123456789abcdef';
  var out = hosts.build_host_payload([row({id: id, name: 'lab'})]);
  assert.strictEqual(out.error, null);
  assert.strictEqual(out.hosts[0].id, id);
  assert.ok(!('tailcat_address' in out.hosts[0]));
  assert.ok(!('hostname' in out.hosts[0]));
  assert.strictEqual(out.hosts[0].tailcat_identity, false);
});

test('an untouched blank Tailcat row is skipped', function () {
  var out = hosts.build_host_payload([row({})]);
  assert.deepStrictEqual(out, {hosts: [], error: null, error_index: -1});
});

test('a new Tailcat row needs an address', function () {
  var out = hosts.build_host_payload([
    {name: 'a', hostname: 'a.lan', port_text: '', keys_text: '',
     username: '', default_command: ''},
    row({name: 'lab'})
  ]);
  assert.strictEqual(out.error_index, 1);
  assert.strictEqual(out.error_field, 'host-tailcat-address');
  // Hosts before the bad row are kept, never wiped (see build_host_payload).
  assert.strictEqual(out.hosts.length, 1);
});

test('a malformed address is reported without echoing it', function () {
  var secret = 'tcSECRET$value';
  var out = hosts.build_host_payload([row({tailcat_address: secret})]);
  assert.ok(out.error);
  assert.strictEqual(out.error.indexOf('SECRET'), -1);
  assert.strictEqual(out.error_field, 'host-tailcat-address');
});

test('a bad port on a Tailcat row is reported', function () {
  var out = hosts.build_host_payload([
    row({tailcat_address: ADDRESS, port_text: '99999'})]);
  assert.strictEqual(out.error_field, 'host-port');
});

test('SSH rows are unaffected by the new keys', function () {
  var out = hosts.build_host_payload([{
    name: '', hostname: 'nas.lan', port_text: '', keys_text: '',
    username: '', default_command: '', transport: 'ssh',
    tailcat_address: '', tailcat_identity: false, id: ''
  }]);
  assert.deepStrictEqual(out.hosts, [{
    name: 'nas.lan', hostname: 'nas.lan', host_key: [], username: '',
    default_command: ''
  }]);
});

test('is_tailcat_value matches only the opaque handle', function () {
  assert.strictEqual(hosts.is_tailcat_value('tailcat:a0123456789abcdef'), true);
  assert.strictEqual(hosts.is_tailcat_value('tailcat:u0123456789abcdef'), true);
  assert.strictEqual(hosts.is_tailcat_value('tailcat:x0123456789abcdef'), false);
  assert.strictEqual(hosts.is_tailcat_value('tailcat:' + ADDRESS), false);
  assert.strictEqual(hosts.is_tailcat_value('nas.lan'), false);
  assert.strictEqual(hosts.is_tailcat_value(''), false);
  assert.strictEqual(hosts.is_tailcat_value(undefined), false);
});

test('command migration keeps Tailcat hosts and never needs their address', function () {
  var stored = [
    {transport: 'tailcat', id: 'u0123456789abcdef', name: 'lab',
     hostname: 'tailcat:u0123456789abcdef', port: 22, host_keys: [],
     username: 'me', default_command: '', tailcat_identity: true,
     tailcat_address_saved: true},
    {name: 'nas', hostname: 'nas.lan', port: 22, host_keys: [],
     username: '', default_command: ''}
  ];
  var found = [{hostname: 'tailcat:u0123456789abcdef', port: 22,
                command: 'tmux attach'}];
  var out = hosts.merge_migrated_commands(stored, found);
  assert.strictEqual(out.changed, true);
  assert.deepStrictEqual(out.payload[0], {
    transport: 'tailcat', id: 'u0123456789abcdef', name: 'lab', port: 22,
    host_key: [], username: 'me', default_command: 'tmux attach',
    tailcat_identity: true
  });
  assert.strictEqual(out.payload[1].hostname, 'nas.lan');
});

test('main.js reads every Tailcat row field', function () {
  var fs = require('node:fs');
  var path = require('node:path');
  var main_js = fs.readFileSync(
    path.join(__dirname, '../../webssh/static/js/main.js'), 'utf8');
  var reads = ['transport: row.find', 'tailcat_address: row.find',
               'tailcat_identity: row.find', "id: row.attr('data-tailcat-id')"];
  for (var i = 0; i < reads.length; i++) {
    assert.ok(main_js.indexOf(reads[i]) !== -1,
              'collect_host_rows no longer reads "' + reads[i] + '"');
  }
});
