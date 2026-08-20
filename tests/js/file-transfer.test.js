'use strict';

var test = require('node:test');
var assert = require('node:assert');
var ft = require('../../webssh/static/js/file-transfer.js');

test('parse_osc7 extracts the path from a file URI', function () {
  assert.strictEqual(ft.parse_osc7('file://myhost/var/log'), '/var/log');
  assert.strictEqual(ft.parse_osc7('file:///var/log'), '/var/log');
});

test('parse_osc7 percent-decodes escaped characters', function () {
  assert.strictEqual(ft.parse_osc7('file://h/tmp/a%20b'), '/tmp/a b');
  assert.strictEqual(ft.parse_osc7('file://h/tmp/%C3%A9'), '/tmp/é');
});

test('parse_osc7 returns null for anything it does not understand', function () {
  // A malformed sequence must leave the last known directory alone rather
  // than silently retargeting uploads to a bogus path.
  assert.strictEqual(ft.parse_osc7(''), null);
  assert.strictEqual(ft.parse_osc7('http://h/var'), null);
  assert.strictEqual(ft.parse_osc7('file://h'), null);
  assert.strictEqual(ft.parse_osc7('nonsense'), null);
});

test('parse_osc7 survives a bad percent escape instead of throwing', function () {
  assert.strictEqual(ft.parse_osc7('file://h/tmp/%ZZ'), null);
});

test('resolve_path returns absolute input unchanged', function () {
  assert.strictEqual(ft.resolve_path('/var/log', '/etc/passwd'), '/etc/passwd');
});

test('resolve_path joins a relative name onto the current directory', function () {
  assert.strictEqual(ft.resolve_path('/var/log', 'syslog'), '/var/log/syslog');
  assert.strictEqual(ft.resolve_path('/var/log/', 'syslog'), '/var/log/syslog');
});

test('resolve_path falls back to the name when no directory is known', function () {
  assert.strictEqual(ft.resolve_path(null, 'syslog'), 'syslog');
  assert.strictEqual(ft.resolve_path('', 'syslog'), 'syslog');
});

test('format_bytes produces short human units', function () {
  assert.strictEqual(ft.format_bytes(0), '0 B');
  assert.strictEqual(ft.format_bytes(512), '512 B');
  assert.strictEqual(ft.format_bytes(1024), '1.0 KB');
  assert.strictEqual(ft.format_bytes(1536), '1.5 KB');
  assert.strictEqual(ft.format_bytes(1048576), '1.0 MB');
  assert.strictEqual(ft.format_bytes(3221225472), '3.0 GB');
});

test('upload_url no longer carries the worker token', function () {
  // The token authorises the whole session; a URL copy would persist in
  // access logs. It travels in the X-Worker-Id header instead.
  var url = ft.upload_url('/tmp/a b', 'a b.txt', false);
  assert.strictEqual(url.indexOf('id='), -1);
  assert.ok(url.indexOf('path=%2Ftmp%2Fa%20b') !== -1);
  assert.ok(url.indexOf('filename=a%20b.txt') !== -1);
  assert.strictEqual(url.indexOf('overwrite=true'), -1);
});

test('upload_url sets overwrite only when asked', function () {
  assert.ok(ft.upload_url('/t', 'f', true).indexOf('overwrite=true') !== -1);
});

test('download_url carries only the ticket', function () {
  var url = ft.download_url('tick et/+value');
  assert.ok(url.indexOf('/transfer/download?') === 0);
  assert.ok(url.indexOf('ticket=tick%20et%2F%2Bvalue') !== -1);
  assert.strictEqual(url.indexOf('id='), -1);
  assert.strictEqual(url.indexOf('path='), -1);
});

test('split_path splits at the last slash', function () {
  assert.deepStrictEqual(ft.split_path('/var/log/sys'),
    {dir: '/var/log', filter: 'sys'});
  assert.deepStrictEqual(ft.split_path('/var/log/'),
    {dir: '/var/log', filter: ''});
  assert.deepStrictEqual(ft.split_path('/a/b/c/file.txt'),
    {dir: '/a/b/c', filter: 'file.txt'});
});

test('split_path preserves root rather than yielding an empty directory', function () {
  // '/passwd' must list '/', not '' -- an empty path would be sent to the
  // server as a relative listing of the home directory.
  assert.deepStrictEqual(ft.split_path('/passwd'), {dir: '/', filter: 'passwd'});
  assert.deepStrictEqual(ft.split_path('/'), {dir: '/', filter: ''});
});

test('split_path reports no directory when the input has no slash', function () {
  // null means "keep the current listing" -- the caller owns that state.
  assert.deepStrictEqual(ft.split_path('syslog'), {dir: null, filter: 'syslog'});
  assert.deepStrictEqual(ft.split_path(''), {dir: null, filter: ''});
});

test('split_path tolerates null and undefined', function () {
  assert.deepStrictEqual(ft.split_path(null), {dir: null, filter: ''});
  assert.deepStrictEqual(ft.split_path(undefined), {dir: null, filter: ''});
});

test('match_entry matches a substring, not only a prefix', function () {
  assert.strictEqual(ft.match_entry('syslog', 'log'), true);
  assert.strictEqual(ft.match_entry('auth.log', 'log'), true);
  assert.strictEqual(ft.match_entry('logrotate.conf', 'log'), true);
});

test('match_entry ignores case in both directions', function () {
  assert.strictEqual(ft.match_entry('Logrotate.conf', 'log'), true);
  assert.strictEqual(ft.match_entry('syslog', 'LOG'), true);
});

test('match_entry with an empty filter matches everything', function () {
  assert.strictEqual(ft.match_entry('anything', ''), true);
  assert.strictEqual(ft.match_entry('anything', '   '), true);
  assert.strictEqual(ft.match_entry('anything', null), true);
});

test('match_entry rejects a non-match', function () {
  assert.strictEqual(ft.match_entry('syslog', 'zzz'), false);
});
