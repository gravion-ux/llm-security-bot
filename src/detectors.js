'use strict';

/**
 * Pattern-based static analyzers.
 *
 * Each detector is a function `(input) => Finding | null` where
 * `input` is a small `{ text, path, line, language }` object. The
 * scanner in src/scanner.js runs every detector over every line
 * (or every small chunk) and aggregates the results.
 *
 * Why patterns and not ML?
 *   The patterns here are intentionally simple and deterministic so
 *   that the tool is fast, testable, and never accidentally calls
 *   a model API. Treat the output as a *triage* list, not as a
 *   proof of exploitability.
 */

const SECRET_RE = /(token|api[_-]?key|secret|password)\s*[:=]\s*["']([^"'\s]{8,})["']/gi;
const BEARER_RE = /Bearer\s+[A-Za-z0-9._\-]{16,}/g;
const INJECTION_PATTERNS = [
  // Direct attempts to override the system prompt
  { id: 'PI-IGNORE-ABOVE',    re: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)/i },
  { id: 'PI-DISREGARD-PREV',  re: /disregard\s+(all\s+)?(previous|prior|above)/i },
  { id: 'PI-SYSTEM-OVERRIDE', re: /system\s*:\s*you\s+are\s+now/i },
  { id: 'PI-NEW-INSTRUCTIONS',re: /new\s+instructions?\s*:/i },
  { id: 'PI-RUN-SHELL',       re: /run\s+(?:the\s+)?(?:following\s+)?(?:bash|sh|cmd|powershell)\s+(?:command|script)/i },
  { id: 'PI-EXFIL',           re: /send\s+(?:the\s+)?(?:results?|data|output)\s+to\s+https?:\/\//i },
  { id: 'PI-BASE64-PAYLOAD',  re: /atob\s*\(\s*["'][A-Za-z0-9+/=]{16,}["']\s*\)/ },
  { id: 'PI-ROLE-SWITCH',     re: /act\s+as\s+(?:an?\s+)?(?:admin|root|developer\s+mode|dan|jailbreak)/i },
];

const SHELL_CALL_RE = /\b(exec|execSync|spawn|spawnSync)\s*\(\s*[`'"]/g;
const SQL_CONCAT_RE  = /\b(SELECT|INSERT|UPDATE|DELETE)\b.{0,200}\+\s*(?:user|input|req\.|request\.|params\.|query)/i;

function detectSecrets(input) {
  const findings = [];
  const t = input.text || '';
  let m;
  SECRET_RE.lastIndex = 0;
  while ((m = SECRET_RE.exec(t)) !== null) {
    findings.push({
      id: 'SECRET-HARDCODED',
      severity: 'HIGH',
      category: 'secrets',
      path: input.path,
      line: input.line,
      evidence: `Possible hardcoded secret: ${m[1]}`,
      remediation: 'Move the secret to environment variable or a secret manager.',
    });
    if (SECRET_RE.lastIndex === m.index) SECRET_RE.lastIndex += 1;
  }
  BEARER_RE.lastIndex = 0;
  while ((m = BEARER_RE.exec(t)) !== null) {
    findings.push({
      id: 'SECRET-BEARER',
      severity: 'HIGH',
      category: 'secrets',
      path: input.path,
      line: input.line,
      evidence: 'Hardcoded bearer token in source.',
      remediation: 'Read the bearer token from a credential store at runtime.',
    });
  }
  return findings;
}

function detectPromptInjection(input) {
  const t = input.text || '';
  const findings = [];
  for (const p of INJECTION_PATTERNS) {
    if (p.re.test(t)) {
      findings.push({
        id: p.id,
        severity: 'HIGH',
        category: 'prompt-injection',
        path: input.path,
        line: input.line,
        evidence: `Pattern matches: ${p.re.source}`,
        remediation:
          'Treat user-supplied text as untrusted. Strip or sandbox the content before it reaches the model, and never let it modify the system prompt.',
      });
    }
  }
  return findings;
}

function detectShellCall(input) {
  const t = input.text || '';
  if (SHELL_CALL_RE.test(t)) {
    return [{
      id: 'SHELL-EXEC',
      severity: 'MEDIUM',
      category: 'unsafe-exec',
      path: input.path,
      line: input.line,
      evidence: 'Shell command construction with exec/spawn on a template literal or string.',
      remediation: 'Use execFile with an argument array; never interpolate user input into a shell command.',
    }];
  }
  return [];
}

function detectSqlConcat(input) {
  const t = input.text || '';
  if (SQL_CONCAT_RE.test(t)) {
    return [{
      id: 'SQL-CONCAT-INPUT',
      severity: 'HIGH',
      category: 'injection',
      path: input.path,
      line: input.line,
      evidence: 'SQL statement built by string concatenation with user input.',
      remediation: 'Use parameterised queries. Never concatenate user input into SQL.',
    }];
  }
  return [];
}

const ALL_DETECTORS = [
  detectSecrets,
  detectPromptInjection,
  detectShellCall,
  detectSqlConcat,
];

function analyzeText(input) {
  const out = [];
  for (const fn of ALL_DETECTORS) {
    out.push(...fn(input));
  }
  return out;
}

module.exports = {
  analyzeText,
  detectSecrets,
  detectPromptInjection,
  detectShellCall,
  detectSqlConcat,
  INJECTION_PATTERNS,
  SECRET_RE,
  BEARER_RE,
};
