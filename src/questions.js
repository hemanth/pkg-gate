import { choice, noul, score } from '@typesafe-ai/sdk';

/**
 * Deterministic decision thresholds.
 * Centralized here for easy review and calibration.
 */
export const THRESHOLDS = {
  // Score >= 2.0 triggers automatic block
  BLOCK_SCORE: 2.0,
  // Score >= 1.2 triggers warning / confirmation
  WARN_SCORE: 1.2,
  // Secret harvesting probability >= 0.6 triggers block
  BLOCK_SECRET_NOUL: 0.6,
  // Secret harvesting probability >= 0.3 triggers warning
  WARN_SECRET_NOUL: 0.3,
  // Arbitrary remote code download/exec >= 0.6 triggers block
  BLOCK_REMOTE_EXEC_NOUL: 0.6,
  // Arbitrary remote code download/exec >= 0.3 triggers warning
  WARN_REMOTE_EXEC_NOUL: 0.3,
  // Confidence floor: decisions with lower confidence route to human review
  CONFIDENCE_FLOOR: 0.5,
};

/**
 * The battery of TypeSafe System One questions asked for each lifecycle script.
 * Evaluated in parallel within a single System One call.
 */
export function createLifecycleQuestions() {
  return {
    script_intent: choice(
      'What is the primary intent and runtime behavior of this npm lifecycle script?',
      {
        build_tool: 'Standard compilation or native build (e.g. node-gyp, esbuild, tsc, cargo)',
        binary_download: 'Downloads official pre-compiled native binaries or assets from a known repository or CDN',
        benign_notice: 'Informational message, donation banner, or benign no-op command',
        system_recon: 'Gathers host system details, environment variables, network interfaces, or user directories',
        credential_access: 'Reads or extracts secrets, authentication tokens (NPM_TOKEN, AWS, SSH keys), or credential files',
        obfuscated_exec: 'Executes obfuscated code, base64 payloads, or pipes curl/wget to bash/sh/node',
        other: 'General package maintenance or utility task',
      }
    ),
    threat_severity: score(
      'How severe is the security risk of running this lifecycle script during npm install?',
      [
        'Safe: standard build or benign command with no external network or secret access',
        'Low risk: fetches known binary from release domain or routine package setup',
        'Suspicious: makes non-standard outbound connections, inspects system environment, or runs encoded commands',
        'Critical threat: credential harvesting, token exfiltration, backdoor dropper, or destructive action',
      ]
    ),
    accesses_secrets: noul(
      'Does this script attempt to access, extract, or transmit environment variables, private credentials, or authentication tokens?',
      {
        true: 'It accesses or exfiltrates environment secrets, auth tokens, or private credentials',
        false: 'It does not attempt to access credentials or environment secrets',
      }
    ),
    remote_execution: noul(
      'Does this script download and execute arbitrary unverified external code or pipe remote scripts directly into a shell?',
      {
        true: 'It downloads and executes unverified remote code or uses curl/wget piping to a shell',
        false: 'It only runs local tools or verified fixed installers',
      }
    ),
  };
}
