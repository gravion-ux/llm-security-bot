'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { scanDir, scanFile, walk } = require('../src/scanner');

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'llm-sec-scan-'));
}

test('walk: returns every supported source file', () => {
  const root = tmp();
  fs.writeFileSync(path.join(root, 'a.js'), 'x = 1');
  fs.writeFileSync(path.join(root, 'b.py'), 'x = 1');
  fs.writeFileSync(path.join(root, 'c.txt'), 'x = 1');           // not scanned
  fs.mkdirSync(path.join(root, 'node_modules'));
  fs.writeFileSync(path.join(root, 'node_modules', 'd.js'), 'x = 1'); // skipped
  const files = walk(root);
  assert.equal(files.length, 2);
  fs.rmSync(root, { recursive: true, force: true });
});

test('scanFile: a file with a hardcoded secret produces a finding', () => {
  const root = tmp();
  const f = path.join(root, 'app.js');
  fs.writeFileSync(f, 'const api_key = "sk-abcdefghijklmnopqrst";');
  const findings = scanFile(f);
  assert.ok(findings.find((x) => x.id === 'SECRET-HARDCODED'));
  fs.rmSync(root, { recursive: true, force: true });
});

test('scanFile: a benign file produces no findings', () => {
  const root = tmp();
  const f = path.join(root, 'app.js');
  fs.writeFileSync(f, 'const x = 1; const y = "hello";');
  const findings = scanFile(f);
  assert.equal(findings.length, 0);
  fs.rmSync(root, { recursive: true, force: true });
});

test('scanDir: aggregates findings across files', () => {
  const root = tmp();
  fs.writeFileSync(path.join(root, 'a.js'), 'api_key = "sk-abcdefghijklmnopqrst"');
  fs.writeFileSync(path.join(root, 'b.py'), 'SELECT * FROM t WHERE id=' + ' + req.query.id');
  const all = scanDir(root);
  assert.ok(all.find((x) => x.id === 'SECRET-HARDCODED'));
  assert.ok(all.find((x) => x.id === 'SQL-CONCAT-INPUT'));
  fs.rmSync(root, { recursive: true, force: true });
});

test('scanFile: large file is reported, not loaded', () => {
  const root = tmp();
  const f = path.join(root, 'big.js');
  // 2 MB of padding
  fs.writeFileSync(f, '// pad\n'.repeat(300_000));
  const findings = scanFile(f);
  assert.equal(findings[0].id, 'SCAN-FILE-TOO-LARGE');
  fs.rmSync(root, { recursive: true, force: true });
});
