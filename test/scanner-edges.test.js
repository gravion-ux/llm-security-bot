'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { scanFile } = require('../src/scanner');

test('scanFile reports a missing file instead of throwing', () => {
  const findings = scanFile('/definitely/missing/file.js');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'SCAN-FILE-UNREADABLE');
});
