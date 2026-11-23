'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '..', 'web', 'index.html'), 'utf8');

const count = (str) => html.split(str).length - 1;
const inFunction = (start, end) => {
  const begin = html.indexOf(start);
  const finish = html.indexOf(end, begin + start.length);
  assert.ok(begin >= 0 && finish > begin, `Missing function boundaries for ${start}`);
  return html.slice(begin, finish);
};

assert.equal(count('id="auto-optimize-modal"'), 1, 'Exactly one auto-optimization dialog is allowed');
assert.equal(count('id="btn-auto-opt-go"'), 1, 'Exactly one execution button is allowed');
assert.match(html, /id="opt-chk-subtargets" class=/, 'Build cleanup must not be preselected');
assert.match(html, /id="opt-chk-evict" class=/, 'Cloud eviction must not be preselected');
assert.match(html, /id="opt-chk-dups" disabled/, 'Bulk duplicate deletion must remain disabled');
assert.match(html, /id="opt-chk-vault" class=/, 'Vault copies must require opt-in');

const planner = inFunction('async function oneClickAutoOptimize()', 'async function executeAutoOptimize()');
assert.match(planner, /const estFree = \(d.safe_caches_bytes \|\| 0\);/, 'Default estimate is only selected safe caches');
const runner = inFunction('async function executeAutoOptimize()', 'state.sessionReclaimedBytes += totalFreed;');
assert.doesNotMatch(runner, /\/api\/delete-local-path/, 'Automatic executor must not call duplicate deletion');
assert.match(runner, /doEvict && !window\.confirm/, 'Cloud evictions require extra explicit confirmation');
assert.match(runner, /\/api\/clean-cache/, 'Safe cleanup remains functional');
assert.match(runner, /\/api\/clean-project-target/, 'Manual build cleanup remains available');
assert.match(runner, /\/api\/offload/, 'Optional vault copy remains available');

console.log('PASS: single dialog, safe defaults, no automatic duplicate deletion, eviction consent, and existing non-destructive workflow routes');
