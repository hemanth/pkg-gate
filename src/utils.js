const useColor = !process.env.NO_COLOR && process.stdout?.isTTY !== false;

export const colors = {
  red: (s) => (useColor ? `\x1b[31m${s}\x1b[0m` : s),
  green: (s) => (useColor ? `\x1b[32m${s}\x1b[0m` : s),
  yellow: (s) => (useColor ? `\x1b[33m${s}\x1b[0m` : s),
  cyan: (s) => (useColor ? `\x1b[36m${s}\x1b[0m` : s),
  dim: (s) => (useColor ? `\x1b[2m${s}\x1b[0m` : s),
  bold: (s) => (useColor ? `\x1b[1m${s}\x1b[0m` : s),
};

export const LIFECYCLE_HOOKS = [
  'preinstall',
  'install',
  'postinstall',
  'prepublish',
  'prepare',
  'preuninstall',
  'postuninstall',
];

/**
 * Extracts lifecycle scripts from a manifest.
 *
 * @param {Record<string, string>} scripts
 * @returns {Array<{ hook: string, command: string }>}
 */
export function extractLifecycleScripts(scripts = {}) {
  const result = [];
  for (const hook of LIFECYCLE_HOOKS) {
    if (typeof scripts[hook] === 'string' && scripts[hook].trim() !== '') {
      result.push({ hook, command: scripts[hook].trim() });
    }
  }
  return result;
}

/**
 * Formats a terminal inspection string for a guard report.
 */
export function formatReport(report) {
  const { name, version, action, score, confidence, findings, reasons } = report;

  const badge =
    action === 'allow'
      ? colors.green('✔ ALLOW')
      : action === 'block'
      ? colors.red('✖ BLOCK')
      : colors.yellow('▲ WARN');

  const lines = [];
  lines.push(`${badge} ${colors.bold(name)}@${version} ${colors.dim(`(risk score: ${score.toFixed(2)}, confidence: ${(confidence * 100).toFixed(0)}%)`)}`);

  if (findings.length === 0) {
    lines.push(`  ${colors.dim('No lifecycle scripts detected (safe to install)')}`);
  } else {
    for (const item of findings) {
      const { hook, command, answers } = item;
      const intent = answers.script_intent?.choice || 'unknown';
      const sev = answers.threat_severity?.score?.toFixed(2) || '0.00';
      const secretsProb = answers.accesses_secrets ? `${(answers.accesses_secrets.noul * 100).toFixed(0)}%` : '0%';
      const remoteProb = answers.remote_execution ? `${(answers.remote_execution.noul * 100).toFixed(0)}%` : '0%';

      lines.push(`  ${colors.cyan(`[${hook}]`)} ${colors.dim(command)}`);
      lines.push(
        `    intent: ${colors.bold(intent)} | severity: ${sev} | secrets: ${secretsProb} | remote-exec: ${remoteProb}`
      );
    }
  }

  if (reasons && reasons.length > 0) {
    lines.push(`  ${colors.dim('Reasons:')}`);
    for (const reason of reasons) {
      lines.push(`    • ${reason}`);
    }
  }

  return lines.join('\n');
}
