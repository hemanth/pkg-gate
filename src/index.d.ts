export interface GuardReport {
  name: string;
  version: string;
  action: 'allow' | 'warn' | 'block';
  score: number;
  confidence: number;
  findings: ScriptFinding[];
  reasons: string[];
  latencyMs: number;
  summary: string;
  isSafe(): boolean;
  inspect(options?: { plain?: boolean; width?: number }): string;
  assertSafe(): boolean;
  structured: StructuredOutput;
  toJSON(): StructuredOutput;
}

export interface ScriptFinding {
  hook: string;
  command: string;
  model: string;
  answers: {
    script_intent?: {
      type: 'choice';
      choice: string;
      confidence: number;
      probabilities: Record<string, number>;
    };
    threat_severity?: {
      type: 'score';
      score: number;
      confidence: number;
      legend?: Record<string, string>;
      probabilities: Record<string, number>;
    };
    accesses_secrets?: {
      type: 'noul';
      noul: number;
    };
    remote_execution?: {
      type: 'noul';
      noul: number;
    };
  };
}

export interface StructuredOutput {
  schemaVersion: string;
  package: {
    name: string;
    version: string;
  };
  verdict: {
    action: 'allow' | 'warn' | 'block';
    score: number;
    confidence: number;
    isSafe: boolean;
  };
  scripts: Array<{
    hook: string;
    command: string;
    model: string;
    intent: {
      choice: string;
      confidence: number;
      probabilities: Record<string, number>;
    } | null;
    severity: {
      score: number;
      confidence: number;
      rubricLevel: string | null;
      probabilities: Record<string, number>;
    } | null;
    accessesSecrets: { probability: number } | null;
    remoteExecution: { probability: number } | null;
  }>;
  policy: {
    thresholds: Record<string, number>;
    reasons: string[];
  };
  telemetry: {
    latencyMs: number;
  };
}

export interface PkgGuardOptions {
  apiKey?: string;
  mock?: boolean;
  script?: boolean;
  blockScore?: number;
  warnScore?: number;
}

/**
 * Pre-install security gate for npm lifecycle scripts using TypeSafe System One.
 */
export default function pkgGuard(
  input: string | object,
  options?: PkgGuardOptions
): Promise<GuardReport>;

export function evaluatePackage(manifest: object, options?: PkgGuardOptions): Promise<GuardReport>;
export function resolveManifest(input: string | object): Promise<object>;
export const THRESHOLDS: Record<string, number>;
export function createLifecycleQuestions(): Record<string, any>;
export function formatReport(report: GuardReport): string;
export function renderTUI(report: GuardReport, options?: { width?: number }): string;
export function drawBox(lines: string[], options?: { width?: number; color?: (s: string) => string }): string;
export function getTerminalWidth(fallback?: number): number;

