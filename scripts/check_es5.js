#!/usr/bin/env node
/*
 * Fails if any of WebSSH's own client-side JS files use `const`, `let`,
 * arrow functions, or template literals. The project targets ES5 in the
 * browser, so these are never allowed in webssh/static/js/ -- except in
 * the vendored third-party files there (jquery, bootstrap, popper, xterm
 * and its addons), which are not ours to rewrite and are excluded below.
 *
 * This is a small hand-rolled scanner rather than a dependency (eslint or
 * similar) so the JS test job stays dependency-free. It tokenizes just
 * enough to ignore comments and string contents, so words like "let" in
 * a comment ("let's ...") or a backtick inside a comment don't produce
 * false positives.
 */

var fs = require('fs');
var path = require('path');

var JS_DIR = path.join(__dirname, '..', 'webssh', 'static', 'js');

var VENDORED_PREFIXES = [
  'jquery', 'bootstrap', 'popper',
  'xterm'  // covers xterm.min.js and every xterm-addon-*.min.js
];

function is_vendored(filename) {
  return VENDORED_PREFIXES.some(function (prefix) {
    return filename.indexOf(prefix) === 0;
  });
}

function target_files() {
  return fs.readdirSync(JS_DIR)
    .filter(function (name) { return /\.js$/.test(name); })
    .filter(function (name) { return !is_vendored(name); })
    .sort();
}

var KEYWORD_RE = /^(const|let)$/;
var IDENT_CHAR_RE = /[A-Za-z0-9_$]/;

// Scans one file's source, returning a list of {line, message} violations.
// Walks the source one character at a time, tracking whether we are
// inside a line comment, a block comment, or a single/double-quoted
// string, so keywords and backticks found there are ignored -- only
// backticks, `const`/`let`, and `=>` appearing in actual code are
// reported.
function scan(source) {
  var violations = [];
  var line = 1;
  var i = 0;
  var n = source.length;
  var state = 'normal';
  var ident = '';
  var ident_line = 0;

  function flush_ident() {
    if (ident && KEYWORD_RE.test(ident)) {
      violations.push({
        line: ident_line,
        message: '`' + ident + '` is not allowed (ES5 only)'
      });
    }
    ident = '';
  }

  while (i < n) {
    var c = source[i];
    var c2 = source[i + 1];

    if (c === '\n') line += 1;

    if (state === 'normal') {
      if (IDENT_CHAR_RE.test(c)) {
        if (!ident) ident_line = line;
        ident += c;
        i += 1;
        continue;
      }
      flush_ident();

      if (c === '/' && c2 === '/') {
        state = 'line_comment';
        i += 2;
        continue;
      }
      if (c === '/' && c2 === '*') {
        state = 'block_comment';
        i += 2;
        continue;
      }
      if (c === '\'') {
        state = 'single_string';
        i += 1;
        continue;
      }
      if (c === '"') {
        state = 'double_string';
        i += 1;
        continue;
      }
      if (c === '`') {
        violations.push({
          line: line,
          message: 'template literal (`` ` ``) is not allowed (ES5 only)'
        });
        state = 'template_literal';
        i += 1;
        continue;
      }
      if (c === '=' && c2 === '>') {
        violations.push({
          line: line,
          message: 'arrow function (`=>`) is not allowed (ES5 only)'
        });
        i += 2;
        continue;
      }
      i += 1;
      continue;
    }

    if (state === 'line_comment') {
      if (c === '\n') state = 'normal';
      i += 1;
      continue;
    }

    if (state === 'block_comment') {
      if (c === '*' && c2 === '/') {
        state = 'normal';
        i += 2;
        continue;
      }
      i += 1;
      continue;
    }

    if (state === 'single_string' || state === 'double_string' ||
        state === 'template_literal') {
      var closer = state === 'single_string' ? '\'' :
        state === 'double_string' ? '"' : '`';
      if (c === '\\') {
        i += 2;  // skip the escaped character, whatever it is
        continue;
      }
      if (c === closer) {
        state = 'normal';
        i += 1;
        continue;
      }
      i += 1;
      continue;
    }
  }
  flush_ident();

  return violations;
}

function main() {
  var files = target_files();
  var failed = false;

  files.forEach(function (name) {
    var full = path.join(JS_DIR, name);
    var source = fs.readFileSync(full, 'utf8');
    var violations = scan(source);
    violations.forEach(function (v) {
      failed = true;
      console.error(
        'webssh/static/js/' + name + ':' + v.line + ': ' + v.message);
    });
  });

  if (failed) {
    console.error('\nES5 check failed.');
    process.exit(1);
  }

  console.log('ES5 check passed (' + files.length + ' files checked).');
}

main();
