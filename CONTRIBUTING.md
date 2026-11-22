# Contributing to llm-security-bot

Thanks for helping! `llm-security-bot` is a pattern-based static analyzer
for code, log lines and LLM input. It detects common prompt-injection
patterns, insecure logging, hardcoded secrets and unsafe shell calls.
The core path is deterministic and makes **no model API calls** — that
is a hard rule, and contributions must keep it that way.

## Ground rules

- **Deterministic, offline core.** No network calls, no telemetry, no
  external services in the analyzer path.
- **Zero runtime dependencies.** Node.js standard library only.
- **Defensive purpose.** Detectors flag risky patterns and explain the
  fix. Do not add features whose purpose is to generate working
  injection payloads or bypasses.

## Development setup

Requires Node.js 18 or newer. There is nothing to install — the project
has no dependencies.

```bash
git clone https://github.com/gravion-ux/llm-security-bot.git
cd llm-security-bot
npm test
```

## Running the tests

```bash
npm test        # node --test over test/detectors, test/scanner, test/cli
npm run demo    # CLI demo over the bundled sample input
```

## Anatomy of a detector

Detectors live in `src/` and match patterns against a line or block of
input, returning findings with a stable id, a severity, a plain-language
detail and a concrete remediation. To add a detector:

1. Implement it alongside the existing detectors and register it so the
   scanner runs it.
2. Add tests in `test/detectors.test.js` with one positive case (input
   that must be flagged) and at least one near-miss negative case (input
   that looks similar but must NOT be flagged — false positives are the
   main quality risk in a pattern-based tool).
3. Mention the new detector in the README's detector list.

## Code style

- Plain CommonJS/ES modules matching the surrounding files; no build
  step, no transpiler.
- Comments explain *why* a pattern is risky, not just what it matches.
- Tests are plain `node:test` functions with descriptive names.

## Pull request workflow

1. Fork and branch from `main`: `feat/<short-name>`, `fix/<short-name>`
   or `detector/<detector-id>`.
2. Run `npm test` and `npm run demo` locally — both must pass.
3. Open the PR against `main` with: what changed, why, and the
   positive/negative test cases you added.
4. CI must be green (Node 18, 20 and 22).
5. One logical change per PR.
