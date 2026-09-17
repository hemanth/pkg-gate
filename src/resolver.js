import { readFile, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';

/**
 * Resolves an input (package name, file path, directory, or object) into a normalized manifest.
 *
 * @param {string | object} input
 * @returns {Promise<{ name: string, version: string, scripts: Record<string, string>, raw: object }>}
 */
export async function resolveManifest(input) {
  if (!input) {
    throw new Error('No package or manifest provided to pkg-gate');
  }

  // Case 1: Plain manifest object
  if (typeof input === 'object' && input !== null) {
    return normalizeManifest(input);
  }

  if (typeof input !== 'string') {
    throw new TypeError(`Expected package name or path string, got ${typeof input}`);
  }

  const trimmed = input.trim();

  // Case 2: Local file path or directory
  if (trimmed.startsWith('.') || trimmed.startsWith('/') || trimmed.endsWith('.json')) {
    return loadLocalManifest(trimmed);
  }

  // Case 3: Check if local directory/file exists with that name before querying registry
  try {
    const localPath = resolve(process.cwd(), trimmed);
    const stats = await stat(localPath);
    if (stats.isDirectory() || stats.isFile()) {
      return loadLocalManifest(localPath);
    }
  } catch {
    // Not a local path, continue to npm registry
  }

  // Case 4: Fetch from npm registry
  return fetchRegistryManifest(trimmed);
}

async function loadLocalManifest(filePath) {
  let target = resolve(process.cwd(), filePath);
  let stats;
  try {
    stats = await stat(target);
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`File or directory not found: "${filePath}". Please pass a valid package.json path or npm package name.`);
    }
    throw err;
  }

  if (stats.isDirectory()) {
    target = join(target, 'package.json');
    try {
      await stat(target);
    } catch (err) {
      if (err.code === 'ENOENT') {
        throw new Error(`Directory "${filePath}" does not contain a package.json file.`);
      }
      throw err;
    }
  }

  try {
    const content = await readFile(target, 'utf8');
    const json = JSON.parse(content);
    return normalizeManifest(json);
  } catch (err) {
    if (err instanceof SyntaxError) {
      throw new Error(`Invalid JSON syntax in "${target}": ${err.message}`);
    }
    throw err;
  }
}


async function fetchRegistryManifest(packageName) {
  // Support scoped packages like @foo/bar or specific versions like foo@1.2.3
  let name = packageName;
  let tagOrVersion = 'latest';

  if (packageName.startsWith('@')) {
    const parts = packageName.split('@');
    if (parts.length === 3) {
      name = `@${parts[1]}`;
      tagOrVersion = parts[2];
    }
  } else if (packageName.includes('@')) {
    const parts = packageName.split('@');
    name = parts[0];
    tagOrVersion = parts[1];
  }

  const encodedName = name.startsWith('@')
    ? `@${encodeURIComponent(name.slice(1))}`
    : encodeURIComponent(name);

  const url = `https://registry.npmjs.org/${encodedName}/${tagOrVersion}`;
  const res = await fetch(url, {
    headers: {
      Accept: 'application/json',
      'User-Agent': 'pkg-gate/0.1.0',
    },
  });

  if (!res.ok) {
    if (res.status === 404) {
      throw new Error(`Package "${packageName}" not found on npm registry`);
    }
    throw new Error(`Failed to fetch "${packageName}" from npm: ${res.status} ${res.statusText}`);
  }

  const json = await res.json();
  return normalizeManifest(json);
}

function normalizeManifest(manifest) {
  return {
    name: manifest.name || 'unnamed-package',
    version: manifest.version || '0.0.0',
    description: manifest.description || '',
    scripts: manifest.scripts || {},
    dependencies: manifest.dependencies || {},
    devDependencies: manifest.devDependencies || {},
    raw: manifest,
  };
}
