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
