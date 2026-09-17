import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import readline from 'node:readline';
import { colors } from './utils.js';

/**
 * Returns current terminal width clamped to readable bounds.
 *
 * @param {number} [fallback=76]
 * @returns {number}
 */
export function getTerminalWidth(fallback = 76) {
  const cols = process.stdout?.columns;
  if (!cols || typeof cols !== 'number' || cols <= 0) {
    return fallback;
  }
  // Clamp between 42 (compact mobile/split-pane) and 92 (clean readable card width)
  return Math.max(42, Math.min(cols - 2, 92));
}

/**
 * Strips ANSI escape codes from a string.
 */
export function stripAnsi(str) {
  return String(str).replace(/\x1b\[[0-9;]*m/g, '');
}

/**
 * Calculates visual display length of a string ignoring ANSI color codes.
 */
export function visualLength(str) {
  return stripAnsi(str).length;
}

/**
 * Truncates a string containing ANSI codes without leaving dangling escape sequences.
 */
export function truncateAnsi(str, maxLen) {
  if (visualLength(str) <= maxLen) return str;
  let len = 0;
  let out = '';
  const regex = /(\x1b\[[0-9;]*m)|([\s\S])/g;
  let match;
  while ((match = regex.exec(str)) !== null) {
    if (match[1]) {
      out += match[1];
    } else if (match[2]) {
      if (len >= maxLen - 1) {
        out += '…\x1b[0m';
        return out;
      }
      out += match[2];
      len++;
    }
  }
  return out;
}

/**
 * Wraps text into lines not exceeding maxWidth.
 */
export function wrapText(text, maxWidth) {
  if (!text || text.length <= maxWidth) {
    return [text || ''];
  }
  const words = text.split(/\s+/);
  const lines = [];
  let current = '';

  for (const word of words) {
    const test = current ? `${current} ${word}` : word;
    if (test.length <= maxWidth) {
      current = test;
    } else {
      if (current) lines.push(current);
      if (word.length > maxWidth) {
        let rem = word;
        while (rem.length > maxWidth) {
          lines.push(rem.slice(0, maxWidth));
          rem = rem.slice(maxWidth);
        }
        current = rem;
      } else {
        current = word;
      }
    }
  }
  if (current) {
    lines.push(current);
  }
  return lines;
}

/**
 * Renders a visual ASCII progress meter.
 *
 * @param {number} ratio - Between 0.0 and 1.0
 * @param {number} [width=16] - Width in characters
 * @returns {string}
 */
export function progressBar(ratio, width = 16) {
  const clamped = Math.max(0, Math.min(1, ratio));
  const filledCount = Math.round(clamped * width);
  const emptyCount = width - filledCount;
  return '█'.repeat(filledCount) + '░'.repeat(emptyCount);
}

/**
 * Wraps a single line intended for drawBox to ensure it never exceeds maxWidth.
 */
function wrapBoxLine(line, maxWidth) {
  const vLen = visualLength(line);
  if (vLen <= maxWidth) {
    return [line];
  }

  // If it's a border divider like '─'.repeat(...)
  if (stripAnsi(line).startsWith('─')) {
    return ['─'.repeat(maxWidth)];
  }

  // Word wrap
  const words = line.split(' ');
  const result = [];
  let current = '';

  for (const word of words) {
    const test = current ? `${current} ${word}` : word;
    if (visualLength(test) <= maxWidth) {
      current = test;
    } else {
      if (current) {
        result.push(current);
      }
      if (visualLength(word) > maxWidth) {
        result.push(truncateAnsi(word, maxWidth));
        current = '';
      } else {
        current = '  ' + word;
      }
    }
  }
  if (current) {
    result.push(current);
  }
  return result.length > 0 ? result : [truncateAnsi(line, maxWidth)];
}

/**
 * Creates a rounded card box responsive to specified or terminal width.
 */
export function drawBox(lines, options = {}) {
  const width = options.width || getTerminalWidth();
  const color = options.color || ((s) => s);
  const innerWidth = Math.max(10, width - 4);

  const topChar = '╭' + '─'.repeat(Math.max(0, width - 2)) + '╮';
  const botChar = '╰' + '─'.repeat(Math.max(0, width - 2)) + '╯';

  const formattedLines = [];

  for (const rawLine of lines) {
    if (rawLine === '') {
      formattedLines.push(`│ ${' '.repeat(innerWidth)} │`);
      continue;
    }

    const sublines = wrapBoxLine(rawLine, innerWidth);
    for (const line of sublines) {
      const vLen = visualLength(line);
      const padding = Math.max(0, innerWidth - vLen);
      formattedLines.push(`│ ${line}${' '.repeat(padding)} │`);
    }
  }

  return [color(topChar), ...formattedLines, color(botChar)].join('\n');
}

/**
 * Renders the rich TUI presentation for a pkg-gate evaluation report.
 * Responsively scales cards, meters, and text to match the terminal width.
 *
 * @param {object} report - The GateReport object
 * @param {object} [options]
 * @param {number} [options.width] - Optional width override
 * @returns {string}
 */
export function renderTUI(report, options = {}) {
  const { name, version, action, score, confidence, findings, reasons, latencyMs } = report;
  const width = options.width || getTerminalWidth();
  const innerWidth = Math.max(10, width - 4);
  const out = [];

  // 1. Header Banner
  const isBlock = action === 'block';
  const isWarn = action === 'warn';

  const bannerColor = isBlock ? colors.red : isWarn ? colors.yellow : colors.green;
  const bannerIcon = isBlock ? '✖' : isWarn ? '▲' : '✔';

  let bannerTitle;
  if (isBlock) {
    bannerTitle = innerWidth < 45 ? 'BLOCK · CRITICAL THREAT' : 'BLOCK · CRITICAL THREAT DETECTED';
  } else if (isWarn) {
    bannerTitle = innerWidth < 45 ? 'WARN · HUMAN REVIEW' : 'WARN · HUMAN REVIEW REQUIRED';
  } else {
    bannerTitle = innerWidth < 45 ? 'ALLOW · SAFE' : 'ALLOW · SAFE TO INSTALL';
  }

  const headerBox = [
    bannerColor(colors.bold(`${bannerIcon}  ${bannerTitle}`)),
  ];

  // In narrow terminals, split package details across two lines
  if (innerWidth < 58) {
    headerBox.push(`${colors.bold(name)}@${version}`);
    const scoreStr = `Threat: ${colors.bold(score.toFixed(2))}/3.00`;
    const confStr = `Conf: ${colors.bold(`${(confidence * 100).toFixed(0)}%`)}`;
    const latStr = latencyMs ? `  ${colors.dim('│')}  ${latencyMs}ms` : '';
    headerBox.push(`${scoreStr}  ${colors.dim('│')}  ${confStr}${latStr}`);
  } else if (innerWidth < 84) {
    const latStr = latencyMs ? `  ${colors.dim('│')}  ${latencyMs}ms` : '';
    headerBox.push(
      `${colors.bold(name)}@${version}  ${colors.dim('│')}  Threat: ${colors.bold(score.toFixed(2))}/3.00  ${colors.dim('│')}  Conf: ${colors.bold(`${(confidence * 100).toFixed(0)}%`)}${latStr}`
    );
  } else {
    const latStr = latencyMs ? `  ${colors.dim('│')}  Latency: ${latencyMs}ms` : '';
    headerBox.push(
      `${colors.bold(name)}@${version}  ${colors.dim('│')}  Threat Score: ${colors.bold(score.toFixed(2))}/3.00  ${colors.dim('│')}  Confidence: ${colors.bold(`${(confidence * 100).toFixed(0)}%`)}${latStr}`
    );
  }

  out.push(drawBox(headerBox, { color: bannerColor, width }));
  out.push('');

  // 2. Clean package (fast-path)
  if (findings.length === 0) {
    const cleanLines = [
      colors.green('✔ No lifecycle hooks found in package.json'),
      colors.dim('Package has no preinstall, install, or postinstall scripts.'),
      innerWidth >= 60
        ? colors.dim('Execution fast-path: 0ms runtime overhead, 0 tokens consumed.')
        : colors.dim('Execution fast-path: 0ms runtime overhead.'),
    ];
    out.push(drawBox(cleanLines, { color: colors.green, width }));
    out.push('');
    return out.join('\n');
  }

  // 3. Render Structured Breakdown per lifecycle script
  for (const item of findings) {
    const { hook, command, answers, model } = item;
    const scriptBoxLines = [];

    // Hook header
    const hookTag = colors.bold(colors.cyan(`[HOOK: ${hook.toUpperCase()}]`));
    const normalizedModel = (model || 'jev-latest').replace(' (offline simulator)', innerWidth < 68 ? ' (sim)' : ' (offline simulator)');
    const modelTag = colors.dim(`model: ${normalizedModel}`);
    if (innerWidth < 50) {
      scriptBoxLines.push(hookTag);
      scriptBoxLines.push(`  ${modelTag}`);
    } else {
      scriptBoxLines.push(`${hookTag}  ${modelTag}`);
    }

    // Command (truncated dynamically to fit inner width)
    const maxCmdLen = Math.max(10, innerWidth - 4);
    const cmdDisplay = command.length > maxCmdLen ? command.slice(0, Math.max(0, maxCmdLen - 3)) + '...' : command;
    scriptBoxLines.push(`${colors.dim('$')} ${colors.bold(cmdDisplay)}`);

    // Divider line matching exact innerWidth
    scriptBoxLines.push('─'.repeat(innerWidth));

    // Responsive progress bar width
    const barWidth = Math.max(6, Math.min(16, Math.floor(innerWidth * 0.22)));

    // Primitive 1: Intent (Choice)
    if (answers.script_intent) {
      const choice = answers.script_intent.choice;
      const intentConf = (answers.script_intent.confidence * 100).toFixed(0);
      const isDangerousIntent = choice === 'credential_access' || choice === 'obfuscated_exec';
      const intentColor = isDangerousIntent ? colors.red : choice === 'system_recon' ? colors.yellow : colors.green;

      scriptBoxLines.push(
        `${colors.bold('TypeSafe Choice  ')} ${colors.dim('·')}  ${colors.cyan('script_intent')}`
      );
      scriptBoxLines.push(
        `  Outcome      : ${intentColor(colors.bold(choice))}  ${colors.dim(`(conf: ${intentConf}%)`)}`
      );

      const probs = answers.script_intent.probabilities || {};
      const sortedProbs = Object.entries(probs)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3);

      const maxLabelLen = Math.max(10, Math.min(17, innerWidth - barWidth - 16));

      for (const [label, p] of sortedProbs) {
        const bar = progressBar(p, barWidth);
        const pStr = `${(p * 100).toFixed(0).padStart(3)}%`;
        const itemColor = label === choice ? intentColor : colors.dim;
        const displayLabel = label.length > maxLabelLen ? label.slice(0, maxLabelLen - 2) + '..' : label;
        scriptBoxLines.push(
          `  ${itemColor(displayLabel.padEnd(maxLabelLen))} [${intentColor(bar)}] ${pStr}`
        );
      }
      scriptBoxLines.push('');
    }

    // Primitive 2: Threat Severity (Score)
    if (answers.threat_severity) {
      const sevScore = answers.threat_severity.score;
      const sevConf = (answers.threat_severity.confidence * 100).toFixed(0);
      const scoreRatio = sevScore / 3.0;
      const scoreBar = progressBar(scoreRatio, barWidth);
      const sevColor = sevScore >= 2.0 ? colors.red : sevScore >= 1.2 ? colors.yellow : colors.green;

      const currentLevelDesc =
        answers.threat_severity.legend?.[Math.round(sevScore)] ||
        (sevScore >= 2.0 ? 'Critical Threat' : sevScore >= 1.0 ? 'Suspicious' : 'Safe / Routine');

      scriptBoxLines.push(
        `${colors.bold('TypeSafe Score   ')} ${colors.dim('·')}  ${colors.cyan('threat_severity (0–3)')}`
      );

      if (innerWidth < 64) {
        scriptBoxLines.push(
          `  Calibrated   : ${sevColor(colors.bold(sevScore.toFixed(2)))}/3.00 [${sevColor(scoreBar)}] (${sevConf}%)`
        );
      } else {
        scriptBoxLines.push(
          `  Calibrated   : ${sevColor(colors.bold(sevScore.toFixed(2)))} / 3.00  [${sevColor(scoreBar)}]  ${colors.dim(`(conf: ${sevConf}%)`)}`
        );
      }

      const maxDescWidth = Math.max(10, innerWidth - 18);
      const descDisplay = currentLevelDesc.length > maxDescWidth
        ? currentLevelDesc.slice(0, Math.max(0, maxDescWidth - 3)) + '...'
        : currentLevelDesc;
      scriptBoxLines.push(
        `  Rubric Level : ${sevColor(descDisplay)}`
      );
      scriptBoxLines.push('');
    }

    // Primitives 3 & 4: Yes/No Judgments (Nouls)
    if (answers.accesses_secrets || answers.remote_execution) {
      scriptBoxLines.push(
        `${colors.bold('TypeSafe Nouls   ')} ${colors.dim('·')}  ${colors.cyan('calibrated yes/no probabilities')}`
      );

      const isCompact = innerWidth < 54;

      if (answers.accesses_secrets) {
        const p = answers.accesses_secrets.noul;
        const pStr = `${(p * 100).toFixed(0).padStart(3)}%`;
        const bar = progressBar(p, barWidth);
        const pColor = p >= 0.6 ? colors.red : p >= 0.3 ? colors.yellow : colors.green;
        const status = p >= 0.6
          ? colors.red(isCompact ? 'RISK' : 'CRITICAL RISK')
          : p >= 0.3
          ? colors.yellow(isCompact ? 'WARN' : 'SUSPICIOUS')
          : colors.green('CLEAN');

        const label = isCompact ? 'secrets' : 'accesses_secrets';
        const labelPadded = label.padEnd(isCompact ? 11 : 16);
        scriptBoxLines.push(
          `  ${labelPadded}  [${pColor(bar)}] ${pStr}  →  ${status}`
        );
      }

      if (answers.remote_execution) {
        const p = answers.remote_execution.noul;
        const pStr = `${(p * 100).toFixed(0).padStart(3)}%`;
        const bar = progressBar(p, barWidth);
        const pColor = p >= 0.6 ? colors.red : p >= 0.3 ? colors.yellow : colors.green;
        const status = p >= 0.6
          ? colors.red(isCompact ? 'RISK' : 'CRITICAL RISK')
          : p >= 0.3
          ? colors.yellow(isCompact ? 'WARN' : 'SUSPICIOUS')
          : colors.green('CLEAN');

        const label = isCompact ? 'remote_exec' : 'remote_execution';
        const labelPadded = label.padEnd(isCompact ? 11 : 16);
        scriptBoxLines.push(
          `  ${labelPadded}  [${pColor(bar)}] ${pStr}  →  ${status}`
        );
      }
    }

    out.push(drawBox(scriptBoxLines, { width }));
    out.push('');
  }

  // 4. Policy Reasons Section
  if (reasons && reasons.length > 0) {
    const reasonsLines = [
      `${colors.bold('Deterministic Policy Decision:')}`,
    ];

    const maxReasonWidth = Math.max(10, innerWidth - 6);
    for (const r of reasons) {
      const wrapped = wrapText(r, maxReasonWidth);
      for (let i = 0; i < wrapped.length; i++) {
        if (i === 0) {
          reasonsLines.push(`  • ${colors.dim(wrapped[i])}`);
        } else {
          reasonsLines.push(`    ${colors.dim(wrapped[i])}`);
        }
      }
    }

    out.push(drawBox(reasonsLines, { width }));
    out.push('');
  }

  return out.join('\n');
}

/**
 * Interactive prompt when action is 'warn'.
 */
export async function promptUserConfirmation(question = 'Proceed with installation despite warning? [y/N] ') {
  if (!process.stdin.isTTY) {
    return false;
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(colors.yellow(`? ${question}`), (answer) => {
      rl.close();
      const normalized = answer.trim().toLowerCase();
      resolve(normalized === 'y' || normalized === 'yes');
    });
  });
}

/**
 * Interactively prompts the user for a package name or path when none is passed.
 *
 * @param {string} [helpText]
 * @returns {Promise<string | null>}
 */
export async function promptForTarget(helpText = '') {
  if (!process.stdin.isTTY) {
    return null;
  }

  const localPkgPath = resolve(process.cwd(), 'package.json');
  const hasLocalPkg = existsSync(localPkgPath);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const promptMsg = hasLocalPkg
    ? `${colors.cyan('?')} Scan local ${colors.bold('./package.json')}? [${colors.bold('Y')}/n] (or enter package name / path): `
    : `${colors.cyan('?')} Enter package name or path to package.json (${colors.dim('or press Enter for help')}): `;

  return new Promise((res) => {
    rl.question(promptMsg, (answer) => {
      rl.close();
      const input = answer.trim();

      if (!input) {
        if (hasLocalPkg) {
          return res('./package.json');
        }
        return res(null);
      }

      if (input.toLowerCase() === 'exit' || input.toLowerCase() === 'quit') {
        process.exit(0);
      }

      if (hasLocalPkg && (input.toLowerCase() === 'y' || input.toLowerCase() === 'yes')) {
        return res('./package.json');
      }

      if (hasLocalPkg && (input.toLowerCase() === 'n' || input.toLowerCase() === 'no')) {
        return res(null);
      }

      if (input === '-h' || input === '--help') {
        return res('--help');
      }

      if (input === '-v' || input === '--version') {
        return res('--version');
      }

      res(input);
    });
  });
}

