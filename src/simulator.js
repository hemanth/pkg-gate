/**
 * Offline evaluation engine.
 * Emits calibrated TypeSafe System One schema answers when running offline or without an API key.
 */
export function simulateLifecycleEvaluation(hookName, scriptContent, pkg) {
  const content = String(scriptContent || '').toLowerCase();
  const rawContent = String(scriptContent || '');

  // High-risk indicators: exfiltration, token theft, reverse shells, obfuscated curl piping
  const stealsSecrets =
    /(?:npm_token|aws_access_key|id_rsa|\.ssh|\.npmrc|\.aws|process\.env|env\s*\|\s*curl)/i.test(rawContent);

  const pipesRemote =
    /(?:curl|wget)\s+.*\|\s*(?:bash|sh|node)|eval\s*\(\s*buffer\.from|eval\s*\(\s*atob/i.test(rawContent);

  const isObfuscated =
    /(?:\\x[0-9a-f]{2}){4,}|(?:[A-Za-z0-9+/]{40,}={0,2})/i.test(rawContent);

  const isRecon =
    /(?:uname\s+-a|whoami|cat\s+\/etc\/passwd|ipconfig|ifconfig|hostname)/i.test(rawContent);

  const isNativeBuild =
    /(?:node-gyp\s+rebuild|cmake-js|prebuild-install|cargo\s+build|tsc\b)/i.test(content);

  const isBinaryDownload =
    /(?:download.*binary|node\s+install\.js|release\/download|github\.com\/.*\/releases)/i.test(content);

  const isNotice =
    /(?:opencollective|fund|echo\s+["'].*thank|exit\s+0)/i.test(content);

  // Derive calibrated probabilities
  let intent = 'other';
  let severityScore = 0.2;
  let secretProb = 0.05;
  let remoteExecProb = 0.05;
  let confidence = 0.92;

  if (stealsSecrets || (pipesRemote && isObfuscated)) {
    intent = stealsSecrets ? 'credential_access' : 'obfuscated_exec';
    severityScore = 2.85;
    secretProb = stealsSecrets ? 0.96 : 0.75;
    remoteExecProb = pipesRemote ? 0.94 : 0.65;
    confidence = 0.89;
  } else if (pipesRemote) {
    intent = 'obfuscated_exec';
    severityScore = 2.45;
    secretProb = 0.40;
    remoteExecProb = 0.92;
    confidence = 0.85;
  } else if (isRecon) {
    intent = 'system_recon';
    severityScore = 1.65;
    secretProb = 0.55;
    remoteExecProb = 0.25;
    confidence = 0.78;
  } else if (isBinaryDownload) {
    intent = 'binary_download';
    severityScore = 0.85;
    secretProb = 0.08;
    remoteExecProb = 0.15;
    confidence = 0.91;
  } else if (isNativeBuild) {
    intent = 'build_tool';
    severityScore = 0.15;
    secretProb = 0.02;
    remoteExecProb = 0.03;
    confidence = 0.98;
  } else if (isNotice) {
    intent = 'benign_notice';
    severityScore = 0.05;
    secretProb = 0.01;
    remoteExecProb = 0.01;
    confidence = 0.99;
  }

  return {
    model: 'jev-latest (offline simulator)',
    answers: {
      script_intent: {
        type: 'choice',
        choice: intent,
        probabilities: {
          [intent]: 0.85,
          other: 0.15,
        },
        confidence,
      },
      threat_severity: {
        type: 'score',
        score: severityScore,
        legend: {
          '0': 'Safe: standard build or benign command with no external network or secret access',
          '1': 'Low risk: fetches known binary from release domain or routine package setup',
          '2': 'Suspicious: makes non-standard outbound connections, inspects system environment, or runs encoded commands',
          '3': 'Critical threat: credential harvesting, token exfiltration, backdoor dropper, or destructive action',
        },
        probabilities: {
          '0': severityScore < 1.0 ? 0.8 : 0.05,
          '1': severityScore >= 0.5 && severityScore < 1.5 ? 0.7 : 0.1,
          '2': severityScore >= 1.5 && severityScore < 2.5 ? 0.75 : 0.1,
          '3': severityScore >= 2.0 ? 0.85 : 0.05,
        },
        confidence,
      },
      accesses_secrets: {
        type: 'noul',
        noul: secretProb,
      },
      remote_execution: {
        type: 'noul',
        noul: remoteExecProb,
      },
    },
    usage: {
      input_tokens: 180,
      output_tokens: 38,
    },
  };
}
