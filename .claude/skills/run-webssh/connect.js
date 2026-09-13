// Playwright helper: launch a browser and get to a connected WebSSH terminal.
// Require it from a throwaway driver script, then drive the page.
//
//   const {open} = require('<skill>/connect.js');
//   const {browser, page} = await open();
//   await page.click('#upload-btn');
//   await page.screenshot({path: 'shot.png'});
//   await browser.close();
const {chromium} = require('playwright');

// Playwright pins one Chromium revision and refuses to start without it, but
// this machine has other revisions already cached. Pointing executablePath at
// whichever is present drives them all fine and avoids a browser download.
function chromePath() {
  const fs = require('fs');
  const root = process.env.HOME + '/.cache/ms-playwright';
  const dir = fs.readdirSync(root)
    .filter(n => /^chromium-\d+$/.test(n))
    .sort((a, b) => parseInt(b.slice(9)) - parseInt(a.slice(9)))[0];
  if (!dir) throw new Error('no cached chromium under ' + root);
  for (const rel of ['chrome-linux64/chrome', 'chrome-linux/chrome']) {
    const p = root + '/' + dir + '/' + rel;
    if (fs.existsSync(p)) return p;
  }
  throw new Error('no chrome binary under ' + root + '/' + dir);
}

async function open(opts = {}) {
  const url = process.env.WEBSSH_URL || 'http://127.0.0.1:8899';
  const port = process.env.WEBSSH_SSH_PORT || '2222';
  const key = process.env.WEBSSH_KEY;
  if (!key) throw new Error('WEBSSH_KEY unset -- eval the output of start-stack.sh first');

  const browser = await chromium.launch({executablePath: chromePath()});
  const page = await browser.newPage({viewport: opts.viewport || {width: 1100, height: 720}});
  page.on('pageerror', e => console.log('  [pageerror]', e.message));
  if (opts.console) page.on('console', m => console.log('  [console]', m.type(), m.text()));

  await page.goto(url);
  await page.waitForSelector('#connect');
  await page.fill('#hostname', '127.0.0.1');
  // The port field lives in the collapsed Advanced section.
  await page.click('#advanced-toggle');
  await page.fill('#port', port);
  await page.fill('#username', require('os').userInfo().username);
  await page.setInputFiles('#privatekey', key);
  await page.click('.btn-connect');

  // The tab's status dot goes green only on a live session. #tab-bar.visible
  // is NOT enough: the bar appears for a tab that failed to connect too, so
  // waiting on it turns a refused connection into a confusing timeout later.
  try {
    await page.waitForSelector('.tab-item .tab-status.connected', {timeout: 20000});
  } catch (e) {
    const status = (await page.textContent('#status').catch(() => '')) || '';
    throw new Error('never connected' + (status.trim() ? ': ' + status.trim() : ''));
  }
  await page.waitForTimeout(2500);
  return {browser, page};
}

// Types a command into the terminal and waits for it to land. Use this to give
// the shell a working directory -- the transfer dialogs pre-fill from the cwd
// the shell reports over OSC 7, which is only set once the prompt redraws.
async function run(page, command) {
  await page.keyboard.type(command + '\n');
  await page.waitForTimeout(1500);
}

module.exports = {open, run, chromePath};
