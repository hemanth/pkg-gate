import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import pkgGuard, { THRESHOLDS, createLifecycleQuestions } from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const fixturesDir = join(__dirname, 'fixtures');

describe('pkg-guard: Pre-install security gate with TypeSafe', () => {
  test('clean package with no scripts is immediately allowed', async () => {
    const report = await pkgGuard(join(fixturesDir, 'clean-pkg.json'), { mock: true });

    assert.equal(report.action, 'allow');
    assert.equal(report.score, 0.0);
    assert.equal(report.confidence, 1.0);
    assert.equal(report.findings.length, 0);
    assert.equal(report.isSafe(), true);
    assert.match(report.inspect(), /ALLOW/);
  });

  test('native addon build (node-gyp rebuild) is allowed', async () => {
    const report = await pkgGuard(join(fixturesDir, 'native-build.json'), { mock: true });

    assert.equal(report.action, 'allow');
    assert.equal(report.isSafe(), true);
    assert.ok(report.score < THRESHOLDS.WARN_SCORE);

    const postinstall = report.findings[0];
    assert.equal(postinstall.answers.script_intent.choice, 'build_tool');
    assert.ok(postinstall.answers.threat_severity.score < 1.0);
  });

  test('official binary downloader is allowed', async () => {
    const report = await pkgGuard(join(fixturesDir, 'binary-download.json'), { mock: true });

    assert.equal(report.action, 'allow');
    assert.equal(report.isSafe(), true);
    assert.ok(report.score < THRESHOLDS.WARN_SCORE);

    const postinstall = report.findings[0];
    assert.equal(postinstall.answers.script_intent.choice, 'binary_download');
  });

  test('credential and token stealer is blocked with critical severity', async () => {
    const report = await pkgGuard(join(fixturesDir, 'credential-theft.json'), { mock: true });

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
    const report = await pkgGuard(join(fixturesDir, 'reverse-shell.json'), { mock: true });

    assert.equal(report.action, 'block');
    assert.equal(report.isSafe(), false);
    assert.ok(report.score >= THRESHOLDS.BLOCK_SCORE);

    const preinstall = report.findings[0];
    assert.equal(preinstall.answers.script_intent.choice, 'obfuscated_exec');
    assert.ok(preinstall.answers.remote_execution.noul >= THRESHOLDS.BLOCK_REMOTE_EXEC_NOUL);
  });

  test('system recon probe triggers warning/elevation', async () => {
    const report = await pkgGuard(join(fixturesDir, 'recon-probe.json'), { mock: true });

    assert.ok(report.action === 'warn' || report.action === 'block');
    assert.ok(report.score >= THRESHOLDS.WARN_SCORE);

    const postinstall = report.findings[0];
    assert.equal(postinstall.answers.script_intent.choice, 'system_recon');
  });

  test('supports inline raw script evaluation', async () => {
    const report = await pkgGuard('node-gyp rebuild', { script: true, mock: true });

    assert.equal(report.action, 'allow');
    assert.equal(report.isSafe(), true);
    assert.equal(report.findings[0].answers.script_intent.choice, 'build_tool');
  });

  test('supports direct manifest object input', async () => {
    const report = await pkgGuard(
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
});
