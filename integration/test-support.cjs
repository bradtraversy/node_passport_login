'use strict';
function recordResult(result) {
  const checks = Array.isArray(result.checks) ? result.checks : result.scenarios || [];
  const total = checks.length || Number(result.checks || result.passed || 0);
  console.log('Integration verification: ' + result.passed + '/' + total + ' checks passed for ' + result.repository);
}
module.exports = { recordResult };
if (require.main === module) recordResult(JSON.parse(require('node:fs').readFileSync(0, 'utf8')));
