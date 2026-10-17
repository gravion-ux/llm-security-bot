'use strict';

/**
 * File scanner.
 *
 * Walks a directory tree and runs every detector in `detectors.js` over
 * each line of each text file. Only files with recognised source-code
 * extensions are scanned. Findings are aggregated per-file.
 *
 * No model API call. No network. The scanner is a pure function
 * over the on-disk file tree.
 */

const fs = require('node:fs');
const path = require('node:path');
const { analyzeText } = require('./detectors');

const EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
  '.py', '.rb', '.go', '.rs', '.java', '.kt',
  '.sh', '.bash', '.ps1',
  '.json', '.yml', '.yaml', '.toml', '.env',
  '.html', '.htm', '.php',
]);

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv']);
const MAX_FILE_BYTES = 1_000_000; // 1 MB

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walk(full));
    } else if (entry.isFile() && EXTENSIONS.has(path.extname(entry.name))) {
      out.push(full);
    }
  }
  return out;
}

function scanFile(file) {
  const stat = fs.statSync(file);
  if (stat.size > MAX_FILE_BYTES) {
    return [{
      id: 'SCAN-FILE-TOO-LARGE',
      severity: 'INFO',
      category: 'scanner',
      path: file,
      line: 0,
      evidence: `File is ${stat.size} bytes (limit ${MAX_FILE_BYTES}); skipped.`,
      remediation: 'Re-run on a smaller scope.',
    }];
  }
  const text = fs.readFileSync(file, 'utf-8');
  const findings = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.length === 0) continue;
    const hits = analyzeText({ text: line, path: file, line: i + 1 });
    findings.push(...hits);
  }
  return findings;
}

function scanDir(root) {
  const files = walk(root);
  const findings = [];
  for (const f of files) findings.push(...scanFile(f));
  return findings;
}

module.exports = { scanDir, scanFile, walk, EXTENSIONS, MAX_FILE_BYTES };
