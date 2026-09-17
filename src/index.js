import { resolveManifest } from './resolver.js';
import { evaluatePackage } from './guard.js';

/**
 * Pre-install security gate for npm lifecycle scripts using TypeSafe System One.
 *
 * @param {string | object} input - Package name ('esbuild'), path ('./package.json'), or manifest object
 * @param {object} [options] - Evaluation options
 * @param {string} [options.apiKey] - TypeSafe API key (falls back to process.env.TYPESAFE_API_KEY)
 * @param {boolean} [options.mock] - Force local offline simulation
 * @param {boolean} [options.script] - Treat string input as a raw script command
 * @returns {Promise<import('./guard.js').GuardReport>}
 */
function looksLikeShellCommand(input) {
  if (typeof input !== 'string') return false;
  const trimmed = input.trim();
  if (trimmed.startsWith('.') || trimmed.startsWith('/') || trimmed.endsWith('.json')) {
    return false;
  }
  return (
    /(\||\&\&|;|\|\||`|\$\(|\b(curl|wget|bash|sh|node -e|eval|exec|sudo|chmod|rm -rf)\b)/.test(trimmed) ||
    (trimmed.includes(' ') && !trimmed.startsWith('@'))
  );
}

export default async function pkgGuard(input, options = {}) {
  const isScript = Boolean(options.script || looksLikeShellCommand(input));

  if (isScript && typeof input === 'string') {
    return evaluatePackage(
      {
        name: 'inline-script',
        version: '0.0.0',
        description: 'Single inline lifecycle script',
        scripts: { postinstall: input },
      },
      options
    );
  }

  const manifest = await resolveManifest(input);
  return evaluatePackage(manifest, options);
}

export { evaluatePackage } from './guard.js';
export { resolveManifest } from './resolver.js';
export { THRESHOLDS, createLifecycleQuestions } from './questions.js';
export { simulateLifecycleEvaluation } from './simulator.js';
export { formatReport } from './utils.js';
export { renderTUI, drawBox, getTerminalWidth } from './tui.js';

