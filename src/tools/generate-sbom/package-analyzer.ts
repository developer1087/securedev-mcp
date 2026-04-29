/**
 * Package analyzer - extract package information from lockfiles
 */

import { existsSync, readFileSync } from 'fs';
import { PackageInfo } from './types';

/**
 * Parse package-lock.json to extract package information
 */
export function parseNpmLockfile(projectPath: string): PackageInfo[] {
  const lockfilePath = `${projectPath}/package-lock.json`;
  if (!existsSync(lockfilePath)) {
    throw new Error('package-lock.json not found');
  }

  const packageJsonPath = `${projectPath}/package.json`;
  let directDeps: Set<string> = new Set();

  // Read package.json to determine direct dependencies
  if (existsSync(packageJsonPath)) {
    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
    if (packageJson.dependencies) {
      Object.keys(packageJson.dependencies).forEach((dep) => directDeps.add(dep));
    }
    if (packageJson.devDependencies) {
      Object.keys(packageJson.devDependencies).forEach((dep) => directDeps.add(dep));
    }
  }

  const lockfile = JSON.parse(readFileSync(lockfilePath, 'utf-8'));
  const packages: PackageInfo[] = [];

  // Parse packages from lockfile v2/v3 format
  if (lockfile.packages) {
    for (const [path, pkg] of Object.entries<any>(lockfile.packages)) {
      // Skip root package
      if (path === '') continue;

      // Extract package name (remove node_modules/ prefix)
      const name = path.replace(/^node_modules\//, '');

      // Determine depth
      const depth = directDeps.has(name) ? 1 : 2;

      packages.push({
        name,
        version: pkg.version || 'unknown',
        ecosystem: 'npm',
        license: pkg.license,
        depth,
        homepage: pkg.homepage,
        repository: typeof pkg.repository === 'string' ? pkg.repository : pkg.repository?.url,
        description: pkg.description,
        author: typeof pkg.author === 'string' ? pkg.author : pkg.author?.name,
      });
    }
  }
  // Fallback to lockfile v1 format
  else if (lockfile.dependencies) {
    for (const [name, pkg] of Object.entries<any>(lockfile.dependencies)) {
      const depth = directDeps.has(name) ? 1 : 2;

      packages.push({
        name,
        version: pkg.version || 'unknown',
        ecosystem: 'npm',
        depth,
      });
    }
  }

  return packages;
}

/**
 * Parse requirements.txt for Python packages
 */
export function parsePythonRequirements(projectPath: string): PackageInfo[] {
  const requirementsPath = `${projectPath}/requirements.txt`;
  if (!existsSync(requirementsPath)) {
    throw new Error('requirements.txt not found');
  }

  const content = readFileSync(requirementsPath, 'utf-8');
  const packages: PackageInfo[] = [];

  for (const line of content.split('\n')) {
    const trimmed = line.trim();

    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Parse package==version or package>=version format
    const match = trimmed.match(/^([a-zA-Z0-9-_]+)(?:[=<>~!]+)?([\d.]+)?/);
    if (match) {
      packages.push({
        name: match[1],
        version: match[2] || 'unknown',
        ecosystem: 'pip',
        depth: 1, // requirements.txt typically only has direct deps
      });
    }
  }

  return packages;
}

/**
 * Auto-detect and parse lockfile
 */
export function parseProjectPackages(projectPath: string): PackageInfo[] {
  // Try npm first
  if (existsSync(`${projectPath}/package-lock.json`)) {
    return parseNpmLockfile(projectPath);
  }

  // Try Python
  if (existsSync(`${projectPath}/requirements.txt`)) {
    return parsePythonRequirements(projectPath);
  }

  throw new Error(
    'No supported lockfile found. Supported: package-lock.json, requirements.txt'
  );
}

/**
 * Extract repository URL from package info for maintainability checks
 */
export function extractRepoUrl(pkg: PackageInfo): string | null {
  if (!pkg.repository) return null;

  // Handle git+https://github.com/user/repo.git format
  let repo = pkg.repository;
  repo = repo.replace(/^git\+/, '');
  repo = repo.replace(/\.git$/, '');

  // Extract github.com URLs
  const match = repo.match(/github\.com[:/]([^/]+\/[^/]+)/);
  if (match) {
    return `https://github.com/${match[1]}`;
  }

  return null;
}
