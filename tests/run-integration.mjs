#!/usr/bin/env node

// Simple integration test runner (no external framework needed)
// Requires Node 20+ (global fetch)

const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  bright: '\x1b[1m',
  reset: '\x1b[0m'
};

function log(message, color = '') {
  process.stdout.write(`${colors[color] || ''}${message}${colors.reset}\n`);
}

async function run(name, fn) {
  log(`\n=== ${name} ===`, 'cyan');
  try {
    const result = await fn();
    if (result?.skipped) {
      log(`SKIPPED: ${name} — ${result.reason || 'preconditions not met'}`, 'yellow');
      return { ok: true, skipped: true };
    }
    if (result === true || result?.ok) {
      log(`PASSED: ${name}`, 'green');
      return { ok: true };
    }
    log(`FAILED: ${name}`, 'red');
    return { ok: false };
  } catch (e) {
    log(`ERROR in ${name}: ${e?.message || e}`, 'red');
    return { ok: false };
  }
}

async function main() {
  const tests = [
    {
      name: 'AKE switching via orchestrator',
      mod: await import('./integration/ake_switch.mjs')
    },
    {
      name: 'Falcon uses Kyber (service-level proof)',
      mod: await import('./integration/falcon_kyber_proof.mjs')
    },
    {
      name: 'Default selection behavior (health + large payload)',
      mod: await import('./integration/default_selection.mjs')
    },
    {
      name: 'Policy overrides payload heuristic',
      mod: await import('./integration/policy_overrides.mjs')
    },
    {
      name: 'Health endpoint semantics',
      mod: await import('./integration/health_semantics.mjs')
    },
    {
      name: 'Failure modes and error semantics',
      mod: await import('./integration/failure_modes.mjs')
    }
  ];

  let failures = 0;
  for (const t of tests) {
    const r = await run(t.name, t.mod.default);
    if (!r.ok) failures += 1;
  }

  if (failures > 0) {
    log(`\n${failures} test(s) failed`, 'red');
    process.exit(1);
  }
  log('\nAll integration tests passed', 'green');
}

main().catch(e => {
  log(`Fatal: ${e?.stack || e}`, 'red');
  process.exit(1);
});
