import readline from 'node:readline';
import { colors } from './utils.js';

/**
 * Renders a visual ASCII progress meter.
 *
 * @param {number} ratio - Between 0.0 and 1.0
 * @param {number} [width=20] - Width in characters
 * @returns {string}
 */
export function progressBar(ratio, width = 16) {
  const clamped = Math.max(0, Math.min(1, ratio));
  const filledCount = Math.round(clamped * width);
  const emptyCount = width - filledCount;
  return '█'.repeat(filledCount) + '░'.repeat(emptyCount);
}

/**
 * Creates a rounded card box.
 */
export function drawBox(lines, options = {}) {
  const width = options.width || 72;
  const color = options.color || ((s) => s);
  const topChar = '╭' + '─'.repeat(width - 2) + '╮';
  const botChar = '╰' + '─'.repeat(width - 2) + '╯';

  const formattedLines = lines.map((line) => {
    // Strip ANSI codes to calculate actual string visual length
    const visualLen = line.replace(/\x1b\[[0-9;]*m/g, '').length;
    const padding = Math.max(0, width - 4 - visualLen);
    return `│ ${line}${' '.repeat(padding)} │`;
  });

  return [color(topChar), ...formattedLines, color(botChar)].join('\n');
}

/**
 * Renders the rich TUI presentation for a pkg-guard evaluation report.
 *
 * @param {object} report - The GuardReport object
 * @returns {string}
 */
export function renderTUI(report) {
  const { name, version, action, score, confidence, findings, reasons, latencyMs } = report;
  const out = [];

  // Header Banner
  const isBlock = action === 'block';
  const isWarn = action === 'warn';
  const isAllow = action === 'allow';

  const bannerColor = isBlock ? colors.red : isWarn ? colors.yellow : colors.green;
  const bannerIcon = isBlock ? '✖' : isWarn ? '▲' : '✔';
  const bannerTitle = isBlock
    ? 'BLOCK · CRITICAL THREAT DETECTED'
    : isWarn
    ? 'WARN · HUMAN REVIEW REQUIRED'
    : 'ALLOW · SAFE TO INSTALL';

  const headerBox = [
    `${bannerColor(colors.bold(`${bannerIcon}  ${bannerTitle}`))}`,
    `${colors.bold(name)}@${version}  ${colors.dim('│')}  Threat Score: ${colors.bold(score.toFixed(2))}/3.00  ${colors.dim('│')}  Confidence: ${colors.bold(`${(confidence * 100).toFixed(0)}%`)}${latencyMs ? `  ${colors.dim('│')}  Latency: ${latencyMs}ms` : ''}`,
  ];

  out.push(drawBox(headerBox, { color: bannerColor, width: 76 }));
  out.push('');

  // If no scripts found, show the clean zero-overhead card
  if (findings.length === 0) {
    out.push(
      drawBox(
        [
          `${colors.green('✔ No lifecycle hooks found in package.json')}`,
          `${colors.dim('Package has no preinstall, install, or postinstall scripts.')}`,
          `${colors.dim('Execution fast-path: 0ms runtime overhead, 0 tokens consumed.')}`,
        ],
        { color: colors.green, width: 76 }
      )
    );
    out.push('');
    return out.join('\n');
  }

  // Render Structured Breakdown per lifecycle script
  for (const item of findings) {
    const { hook, command, answers, model } = item;
    const scriptBoxLines = [];

    scriptBoxLines.push(`${colors.bold(colors.cyan(`[HOOK: ${hook.toUpperCase()}]`))}  ${colors.dim(`model: ${model || 'jev-latest'}`)}`);
    scriptBoxLines.push(`${colors.dim('$')} ${colors.bold(command.length > 64 ? command.slice(0, 61) + '...' : command)}`);
    scriptBoxLines.push('─'.repeat(72));

    // Structured Primitive 1: Intent (Choice)
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

      // Show top probability distribution
      const probs = answers.script_intent.probabilities || {};
      const sortedProbs = Object.entries(probs)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3);

      for (const [label, p] of sortedProbs) {
        const bar = progressBar(p, 14);
        const pStr = `${(p * 100).toFixed(0).padStart(3)}%`;
        const itemColor = label === choice ? intentColor : colors.dim;
        scriptBoxLines.push(
          `  ${itemColor(label.padEnd(17))} [${intentColor(bar)}] ${pStr}`
        );
      }
      scriptBoxLines.push('');
    }

    // Structured Primitive 2: Threat Severity (Score)
    if (answers.threat_severity) {
      const sevScore = answers.threat_severity.score;
      const sevConf = (answers.threat_severity.confidence * 100).toFixed(0);
      const scoreRatio = sevScore / 3.0;
      const scoreBar = progressBar(scoreRatio, 16);
      const sevColor = sevScore >= 2.0 ? colors.red : sevScore >= 1.2 ? colors.yellow : colors.green;

      const currentLevelDesc =
        answers.threat_severity.legend?.[Math.round(sevScore)] ||
        (sevScore >= 2.0 ? 'Critical Threat' : sevScore >= 1.0 ? 'Suspicious' : 'Safe / Routine');

      scriptBoxLines.push(
        `${colors.bold('TypeSafe Score   ')} ${colors.dim('·')}  ${colors.cyan('threat_severity (0–3)')}`
      );
      scriptBoxLines.push(
        `  Calibrated   : ${sevColor(colors.bold(sevScore.toFixed(2)))} / 3.00  [${sevColor(scoreBar)}]  ${colors.dim(`(conf: ${sevConf}%)`)}`
      );
      scriptBoxLines.push(
        `  Rubric Level : ${sevColor(currentLevelDesc.length > 52 ? currentLevelDesc.slice(0, 49) + '...' : currentLevelDesc)}`
      );
      scriptBoxLines.push('');
    }

    // Structured Primitives 3 & 4: Yes/No Judgments (Nouls)
    if (answers.accesses_secrets || answers.remote_execution) {
      scriptBoxLines.push(
        `${colors.bold('TypeSafe Nouls   ')} ${colors.dim('·')}  ${colors.cyan('calibrated yes/no probabilities')}`
      );

      if (answers.accesses_secrets) {
        const p = answers.accesses_secrets.noul;
        const pStr = `${(p * 100).toFixed(0).padStart(3)}%`;
        const bar = progressBar(p, 14);
        const pColor = p >= 0.6 ? colors.red : p >= 0.3 ? colors.yellow : colors.green;
        const status = p >= 0.6 ? colors.red('CRITICAL RISK') : p >= 0.3 ? colors.yellow('SUSPICIOUS') : colors.green('CLEAN');
        scriptBoxLines.push(
          `  accesses_secrets  [${pColor(bar)}] ${pStr}  →  ${status}`
        );
      }

      if (answers.remote_execution) {
        const p = answers.remote_execution.noul;
        const pStr = `${(p * 100).toFixed(0).padStart(3)}%`;
        const bar = progressBar(p, 14);
        const pColor = p >= 0.6 ? colors.red : p >= 0.3 ? colors.yellow : colors.green;
        const status = p >= 0.6 ? colors.red('CRITICAL RISK') : p >= 0.3 ? colors.yellow('SUSPICIOUS') : colors.green('CLEAN');
        scriptBoxLines.push(
          `  remote_execution  [${pColor(bar)}] ${pStr}  →  ${status}`
        );
      }
    }

    out.push(drawBox(scriptBoxLines, { width: 76 }));
    out.push('');
  }

  // Policy Reasons Section
  if (reasons && reasons.length > 0) {
    const reasonsLines = [
      `${colors.bold('Deterministic Policy Decision:')}`,
      ...reasons.map((r) => `  • ${colors.dim(r)}`),
    ];
    out.push(drawBox(reasonsLines, { width: 76 }));
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
