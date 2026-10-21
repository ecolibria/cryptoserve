/**
 * Multi-ecosystem manifest parser and crypto package detector.
 *
 * Parses go.mod, requirements.txt, pyproject.toml, Cargo.toml, pom.xml
 * and identifies known crypto packages.
 * Ported from backend/app/core/dependency_scanner.py.
 * Zero dependencies.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, basename } from 'node:path';
import { CRYPTO_PACKAGES, lookupPackage } from './crypto-registry.mjs';
import { stripTerminalUnsafe } from './waivers.mjs';

// Re-export for backward compatibility
export { CRYPTO_PACKAGES };

/**
 * The most characters of a dependency version any report carries.
 *
 * A version is the manifest's own text, and it reaches `scan`, `gate` and the
 * CBOM, inside the purl too. A finding's `evidence` (80) and a waiver's rule
 * (80) and reason (200) are capped where they are built, for the same reason.
 * This one is set above those so that a long range, git URL or tarball URL
 * survives whole up to 256 characters. What reads a version tests that it is
 * set or compares it with `unknown`, `builtin` or `source-code`. All three are
 * shorter than the cap, so a capped version answers each of those as the
 * whole one did.
 *
 * Applied after the value is cleaned, here for every other ecosystem and in
 * `scanProject` for npm, so every output carries the same value.
 */
export const VERSION_CAP = 256;

// ---------------------------------------------------------------------------
// Manifest parsers
// ---------------------------------------------------------------------------

/**
 * Parse go.mod — extract module dependencies.
 */
export function parseGoMod(content) {
  const deps = [];
  // Match require block
  const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
  const lines = requireBlock ? requireBlock[1].split('\n') : content.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed === 'require') continue;
    const match = trimmed.match(/^([a-zA-Z0-9.\/_-]+)\s+(v[\d.]+[a-zA-Z0-9._-]*)/);
    if (match) {
      deps.push({ name: match[1], version: match[2] });
    }
  }

  // Also match single-line require directives
  const singleReqs = content.matchAll(/^require\s+([a-zA-Z0-9.\/_-]+)\s+(v[\d.]+[a-zA-Z0-9._-]*)/gm);
  for (const m of singleReqs) {
    if (!deps.some(d => d.name === m[1])) {
      deps.push({ name: m[1], version: m[2] });
    }
  }

  return deps;
}

/**
 * Parse requirements.txt — extract package==version lines.
 */
export function parseRequirementsTxt(content) {
  const deps = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
    const match = trimmed.match(/^([a-zA-Z0-9._-]+)(?:\[.*?\])?\s*(?:([<>=!~]+)\s*(.*))?$/);
    if (match) {
      deps.push({
        name: match[1].toLowerCase(),
        version: match[3] || null,
      });
    }
  }
  return deps;
}

/**
 * Parse pyproject.toml — extract [project.dependencies] section.
 */
export function parsePyprojectToml(content) {
  const deps = [];
  // Match dependencies array
  const depsMatch = content.match(/\[project\]\s*[\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/);
  if (depsMatch) {
    const lines = depsMatch[1].split('\n');
    for (const line of lines) {
      const match = line.match(/["']([a-zA-Z0-9._-]+)(?:\[.*?\])?(?:([<>=!~]+)([\d.]+))?/);
      if (match) {
        deps.push({ name: match[1].toLowerCase(), version: match[3] || null });
      }
    }
  }

  // Also check [tool.poetry.dependencies]
  const poetryMatch = content.match(/\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\[|$)/);
  if (poetryMatch) {
    const lines = poetryMatch[1].split('\n');
    for (const line of lines) {
      const match = line.match(/^([a-zA-Z0-9._-]+)\s*=\s*(?:"([^"]+)"|{.*?version\s*=\s*"([^"]+)")/);
      if (match && match[1] !== 'python') {
        const name = match[1].toLowerCase();
        if (!deps.some(d => d.name === name)) {
          deps.push({ name, version: match[2] || match[3] || null });
        }
      }
    }
  }

  return deps;
}

/**
 * Parse Cargo.toml — extract [dependencies] section.
 */
export function parseCargoToml(content) {
  const deps = [];
  const depsMatch = content.match(/\[dependencies\]([\s\S]*?)(?:\[|$)/);
  if (!depsMatch) return deps;

  for (const line of depsMatch[1].split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    // name = "version" or name = { version = "x.y.z" }
    const simpleMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
    if (simpleMatch) {
      deps.push({ name: simpleMatch[1], version: simpleMatch[2] });
      continue;
    }
    const complexMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{.*?version\s*=\s*"([^"]+)"/);
    if (complexMatch) {
      deps.push({ name: complexMatch[1], version: complexMatch[2] });
    }
  }
  return deps;
}

/**
 * Parse pom.xml — extract <dependency> blocks.
 */
export function parsePomXml(content) {
  const deps = [];
  const depRegex = /<dependency>\s*<groupId>(.*?)<\/groupId>\s*<artifactId>(.*?)<\/artifactId>(?:\s*<version>(.*?)<\/version>)?/g;
  let match;
  while ((match = depRegex.exec(content)) !== null) {
    deps.push({
      name: `${match[1]}:${match[2]}`,
      version: match[3] || null,
      groupId: match[1],
      artifactId: match[2],
    });
  }
  return deps;
}

// ---------------------------------------------------------------------------
// Manifest detection and scanning
// ---------------------------------------------------------------------------

const MANIFEST_FILES = [
  { file: 'package.json', ecosystem: 'npm', parser: null }, // npm handled by main scanner
  { file: 'go.mod', ecosystem: 'go', parser: parseGoMod },
  { file: 'go.sum', ecosystem: 'go', parser: null },
  { file: 'requirements.txt', ecosystem: 'pypi', parser: parseRequirementsTxt },
  { file: 'pyproject.toml', ecosystem: 'pypi', parser: parsePyprojectToml },
  { file: 'Cargo.toml', ecosystem: 'cargo', parser: parseCargoToml },
  { file: 'pom.xml', ecosystem: 'maven', parser: parsePomXml },
];

/**
 * Scan a project directory for manifests and identify crypto dependencies.
 * Returns array of library entries compatible with scanner.mjs output.
 */
export function scanManifests(projectDir) {
  const results = [];
  const seen = new Set();

  for (const { file, ecosystem, parser } of MANIFEST_FILES) {
    if (!parser) continue; // npm handled by main scanner

    const manifestPath = join(projectDir, file);
    if (!existsSync(manifestPath)) continue;

    let content;
    try { content = readFileSync(manifestPath, 'utf-8'); }
    catch { continue; }

    const deps = parser(content);

    for (const dep of deps) {
      const pkg = lookupPackage(dep.name, ecosystem);
      if (pkg && !seen.has(`${ecosystem}:${pkg.name}`)) {
        seen.add(`${ecosystem}:${pkg.name}`);
        results.push({
          name: pkg.name,
          // The parsers above capture a version as `.*` or `[^"]+`, so it is the
          // manifest's own text. Cleaned and capped once here for every
          // ecosystem, so `scan`, `gate` and the CBOM purl all carry the same
          // value.
          version: stripTerminalUnsafe(dep.version || '').slice(0, VERSION_CAP) || 'unknown',
          algorithms: pkg.algorithms,
          quantumRisk: pkg.quantumRisk,
          category: pkg.category,
          ecosystem,
          source: file,
          isDeprecated: pkg.isDeprecated || false,
        });
      }
    }
  }

  return results;
}
