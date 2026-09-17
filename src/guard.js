import { TypeSafeClient } from '@typesafe-ai/sdk';
import { createLifecycleQuestions, THRESHOLDS } from './questions.js';
import { simulateLifecycleEvaluation } from './simulator.js';
import { extractLifecycleScripts, formatReport } from './utils.js';
import { renderTUI } from './tui.js';

/**
 * Evaluates a package manifest or lifecycle script against TypeSafe System One.
 *
 * @param {object} manifest - Normalized package manifest
 * @param {object} [options]
 * @param {string} [options.apiKey] - TypeSafe API key
 * @param {TypeSafeClient} [options.client] - Existing TypeSafeClient instance
 * @param {boolean} [options.mock] - Force local offline simulation
 * @param {number} [options.blockScore] - Custom score threshold for blocking
 * @param {number} [options.warnScore] - Custom score threshold for warning
 * @returns {Promise<GuardReport>}
 */
export async function evaluatePackage(manifest, options = {}) {
  const startTime = performance.now();
  const scripts = extractLifecycleScripts(manifest.scripts);

  // Fast path: No lifecycle scripts at all
  if (scripts.length === 0) {
    const report = createReport({
      name: manifest.name,
      version: manifest.version,
      action: 'allow',
      score: 0.0,
      confidence: 1.0,
      findings: [],
      reasons: ['No lifecycle scripts found; package cannot execute arbitrary code on install'],
      latencyMs: Math.round(performance.now() - startTime),
    });
    return report;
  }

  const apiKey = options.apiKey || process.env.TYPESAFE_API_KEY;
  const useSimulator = options.mock || !apiKey;

  let client = null;
  if (!useSimulator) {
    client = options.client || new TypeSafeClient({ apiKey });
  }

  const findings = [];
  const reasons = [];

  const blockScore = options.blockScore ?? THRESHOLDS.BLOCK_SCORE;
  const warnScore = options.warnScore ?? THRESHOLDS.WARN_SCORE;

  // Evaluate each lifecycle script in parallel (speculative fan-out)
  const evaluations = await Promise.all(
    scripts.map(async ({ hook, command }) => {
      const state = {
        package: {
          name: manifest.name,
          version: manifest.version,
          description: manifest.description,
        },
        lifecycle_hook: hook,
        script_content: command,
      };

      if (useSimulator) {
        return {
          hook,
          command,
          result: simulateLifecycleEvaluation(hook, command, manifest),
        };
      }

      try {
        const result = await client.systemOne({
          state,
          questions: createLifecycleQuestions(),
        });
        return { hook, command, result };
      } catch (err) {
        // Fall back to simulator if API call fails
        return {
          hook,
          command,
          result: simulateLifecycleEvaluation(hook, command, manifest),
          fallbackReason: err.message,
        };
      }
    })
  );

  let maxScore = 0.0;
  let minConfidence = 1.0;
  let maxSecretProb = 0.0;
  let maxRemoteProb = 0.0;

  for (const { hook, command, result } of evaluations) {
    const answers = result.answers;
    findings.push({
      hook,
      command,
      answers,
      model: result.model,
    });

    const intent = answers.script_intent?.choice;
    const intentConfidence = answers.script_intent?.confidence ?? 1.0;
    const severity = answers.threat_severity?.score ?? 0.0;
    const severityConfidence = answers.threat_severity?.confidence ?? 1.0;
    const secretNoul = answers.accesses_secrets?.noul ?? 0.0;
    const remoteNoul = answers.remote_execution?.noul ?? 0.0;

    if (severity > maxScore) maxScore = severity;
    if (secretNoul > maxSecretProb) maxSecretProb = secretNoul;
    if (remoteNoul > maxRemoteProb) maxRemoteProb = remoteNoul;

    const lowestQuestionConfidence = Math.min(intentConfidence, severityConfidence);
    if (lowestQuestionConfidence < minConfidence) minConfidence = lowestQuestionConfidence;

    // Reason tracking
    if (secretNoul >= THRESHOLDS.WARN_SECRET_NOUL) {
      reasons.push(`[${hook}] Probable credential access (${(secretNoul * 100).toFixed(0)}% probability)`);
    }
    if (remoteNoul >= THRESHOLDS.WARN_REMOTE_EXEC_NOUL) {
      reasons.push(`[${hook}] Remote code download or execution detected (${(remoteNoul * 100).toFixed(0)}% probability)`);
    }
    if (intent === 'credential_access' || intent === 'obfuscated_exec') {
      reasons.push(`[${hook}] High-risk script intent classified as "${intent}"`);
    }
    if (severity >= warnScore) {
      reasons.push(`[${hook}] Threat severity score elevated (${severity.toFixed(2)} / 3.0)`);
    }
  }

  // Gating decision
  let action = 'allow';

  const isCritical =
    maxScore >= blockScore ||
    maxSecretProb >= THRESHOLDS.BLOCK_SECRET_NOUL ||
    maxRemoteProb >= THRESHOLDS.BLOCK_REMOTE_EXEC_NOUL;

  const isSuspicious =
    maxScore >= warnScore ||
    maxSecretProb >= THRESHOLDS.WARN_SECRET_NOUL ||
    maxRemoteProb >= THRESHOLDS.WARN_REMOTE_EXEC_NOUL;

  const isUncertain = minConfidence < THRESHOLDS.CONFIDENCE_FLOOR;

  if (isCritical) {
    action = 'block';
  } else if (isSuspicious) {
    action = 'warn';
  } else if (isUncertain) {
    // Confidence-gated routing: uncertainty prompts human review
    action = 'warn';
    reasons.push(`Low evaluation confidence (${(minConfidence * 100).toFixed(0)}%); human verification required`);
  }

  if (action === 'allow' && reasons.length === 0) {
    reasons.push('Lifecycle scripts verified benign (standard build or verified binary)');
  }

  const latencyMs = Math.round(performance.now() - startTime);

  return createReport({
    name: manifest.name,
    version: manifest.version,
    action,
    score: maxScore,
    confidence: minConfidence,
    findings,
    reasons,
    latencyMs,
  });
}

function createReport(data) {
  const report = {
    ...data,
    isSafe() {
      return this.action === 'allow';
    },
    inspect(options = {}) {
      if (options.plain) {
        return formatReport(this);
      }
      return renderTUI(this);
    },
    assertSafe() {
      if (this.action === 'block') {
        throw new Error(`Package "${this.name}@${this.version}" blocked: ${this.reasons.join(', ')}`);
      }
      return true;
    },
    get summary() {
      return `${this.action.toUpperCase()}: ${this.name}@${this.version} (score: ${this.score.toFixed(2)}, conf: ${(this.confidence * 100).toFixed(0)}%)`;
    },
    get structured() {
      return {
        schemaVersion: '1.0.0',
        package: {
          name: this.name,
          version: this.version,
        },
        verdict: {
          action: this.action,
          score: Number(this.score.toFixed(2)),
          confidence: Number(this.confidence.toFixed(2)),
          isSafe: this.isSafe(),
        },
        scripts: this.findings.map((f) => ({
          hook: f.hook,
          command: f.command,
          model: f.model,
          intent: f.answers.script_intent
            ? {
                choice: f.answers.script_intent.choice,
                confidence: Number(f.answers.script_intent.confidence.toFixed(2)),
                probabilities: f.answers.script_intent.probabilities,
              }
            : null,
          severity: f.answers.threat_severity
            ? {
                score: Number(f.answers.threat_severity.score.toFixed(2)),
                confidence: Number(f.answers.threat_severity.confidence.toFixed(2)),
                rubricLevel: f.answers.threat_severity.legend?.[Math.round(f.answers.threat_severity.score)] || null,
                probabilities: f.answers.threat_severity.probabilities,
              }
            : null,
          accessesSecrets: f.answers.accesses_secrets
            ? {
                probability: Number(f.answers.accesses_secrets.noul.toFixed(2)),
              }
            : null,
          remoteExecution: f.answers.remote_execution
            ? {
                probability: Number(f.answers.remote_execution.noul.toFixed(2)),
              }
            : null,
        })),
        policy: {
          thresholds: THRESHOLDS,
          reasons: this.reasons,
        },
        telemetry: {
          latencyMs: this.latencyMs,
        },
      };
    },
    toJSON() {
      return this.structured;
    },
  };

  return report;
}
