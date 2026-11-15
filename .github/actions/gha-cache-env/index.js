// gha-cache-env — re-export the Actions cache runtime env into
// GITHUB_ENV. JS actions receive ACTIONS_RUNTIME_TOKEN /
// ACTIONS_CACHE_URL / ACTIONS_RESULTS_URL from the runner; `run:`
// steps do not, so without this hop `docker buildx type=gha` cache
// args stay empty and every release rebuilds from scratch.
const fs = require('fs');

const VARS = [
  'ACTIONS_RUNTIME_TOKEN',
  'ACTIONS_CACHE_URL',
  'ACTIONS_RESULTS_URL',
];

const lines = VARS.filter((v) => process.env[v])
  .map((v) => `${v}=${process.env[v]}`);

if (lines.length > 0 && process.env.GITHUB_ENV) {
  fs.appendFileSync(process.env.GITHUB_ENV, lines.join('\n') + '\n');
}
