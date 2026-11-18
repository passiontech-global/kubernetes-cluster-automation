// gha-cache-env — re-export the Actions cache runtime env into
// GITHUB_ENV. JS actions receive ACTIONS_RUNTIME_TOKEN /
// ACTIONS_CACHE_URL / ACTIONS_RESULTS_URL / ACTIONS_CACHE_SERVICE_V2
// from the runner; `run:` steps do not, so without this hop
// `docker buildx type=gha` cache args stay empty (or fall back to the
// sunset v1 cache endpoint when ACTIONS_CACHE_SERVICE_V2 is missing).
const fs = require('fs');

const VARS = [
  'ACTIONS_RUNTIME_TOKEN',
  'ACTIONS_CACHE_URL',
  'ACTIONS_RESULTS_URL',
  'ACTIONS_CACHE_SERVICE_V2',
];

// Values here are runner-supplied, but a raw CR/LF would break out of
// the single `::add-mask::…` command on stdout or append an attacker-
// chosen line to GITHUB_ENV (workflow-command injection). These vars
// are URLs/tokens and never legitimately carry a newline: strip those
// bytes BEFORE either write, and use the same cleaned value for both
// the mask and the export so what gets masked is what later steps see.
function stripNewlines(value) {
  return value.replace(/[\r\n]/g, '');
}

// ACTIONS_RUNTIME_TOKEN is a bearer credential for the cache service.
// Register it with the runner's secret mask BEFORE exporting it via
// GITHUB_ENV: later `run:` steps can see the env, and an echoed env
// (or a failing command that dumps it) must stay redacted in the log.
// The runner consumes ::add-mask:: commands itself — the value is
// never printed as ordinary output.
const runtimeToken = process.env.ACTIONS_RUNTIME_TOKEN
  ? stripNewlines(process.env.ACTIONS_RUNTIME_TOKEN)
  : '';
if (runtimeToken) {
  process.stdout.write(`::add-mask::${runtimeToken}\n`);
}

const lines = VARS.filter((v) => process.env[v])
  .map((v) => `${v}=${stripNewlines(process.env[v])}`);

if (lines.length > 0 && process.env.GITHUB_ENV) {
  fs.appendFileSync(process.env.GITHUB_ENV, lines.join('\n') + '\n');
}
