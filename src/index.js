'use strict';

/**
 * llm-security-bot — public entry point (package.json "main").
 *
 * Re-exports the library API so the package can be used programmatically:
 *
 *   const { analyzeText, scanDir } = require('llm-security-bot');
 *
 * The CLI lives in ./cli.js (bin "llm-sec"); it is not loaded here because
 * it runs on execution.
 */

module.exports = {
  ...require('./detectors'),
  ...require('./scanner'),
};
