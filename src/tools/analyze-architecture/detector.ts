/**
 * Component detector - extract architecture components from config files
 */

import { existsSync, readFileSync, readdirSync } from 'fs';
import { DetectedComponent, DockerCompose, DockerComposeService } from './types';

/**
 * Parse docker-compose.yml
 */
function parseDockerCompose(path: string): DetectedComponent[] {
  if (!existsSync(path)) return [];

  try {
    const content = readFileSync(path, 'utf-8');
    // Simple YAML parsing (production should use a proper YAML library)
    const components: DetectedComponent[] = [];

    // Parse as JSON-like structure (works for simple docker-compose files)
    // In production, use js-yaml library
    const lines = content.split('\n');
    let currentService: string | null = null;
    let inServices = false;
    const services: Record<string, Partial<DockerComposeService>> = {};

    for (const line of lines) {
      const trimmed = line.trim();

      if (trimmed.startsWith('services:')) {
        inServices = true;
        continue;
      }

      if (inServices && line.match(/^[a-zA-Z0-9_-]+:/) && !line.startsWith('  ')) {
        // End of services section
        inServices = false;
      }

      if (inServices && line.match(/^  [a-zA-Z0-9_-]+:/)) {
        currentService = line.match(/^  ([a-zA-Z0-9_-]+):/)?.[1] || null;
        if (currentService) {
          services[currentService] = {};
        }
      }

      if (currentService && trimmed.startsWith('image:')) {
        const image = trimmed.replace('image:', '').trim();
        if (!services[currentService]) services[currentService] = {};
        services[currentService].image = image;
      }

      if (currentService && trimmed.startsWith('ports:')) {
        if (!services[currentService].ports) services[currentService].ports = [];
      }

      if (currentService && trimmed.match(/^- "?\d+:\d+"?/)) {
        const portMatch = trimmed.match(/- "?(\d+):(\d+)"?/);
        if (portMatch) {
          if (!services[currentService].ports) services[currentService].ports = [];
          services[currentService].ports!.push(`${portMatch[1]}:${portMatch[2]}`);
        }
      }
    }

    // Convert to components
    for (const [name, service] of Object.entries(services)) {
      const image = service.image || '';
      let type: DetectedComponent['type'] = 'service';

      // Infer type from image name
      if (image.includes('postgres') || image.includes('mysql') || image.includes('mongo')) {
        type = 'database';
      } else if (image.includes('redis') || image.includes('memcached')) {
        type = 'cache';
      } else if (image.includes('rabbitmq') || image.includes('kafka')) {
        type = 'queue';
      } else if (image.includes('nginx') || image.includes('traefik')) {
        type = 'proxy';
      }

      components.push({
        name,
        type,
        technology: image,
        ports: service.ports?.map((p) => {
          if (typeof p === 'string') {
            return parseInt(p.split(':')[0]);
          }
          return p.published || p.target;
        }) || [],
        detectedFrom: path,
        confidence: 'high',
      });
    }

    return components;
  } catch (error) {
    console.warn(`Failed to parse docker-compose.yml: ${error}`);
    return [];
  }
}

/**
 * Parse .env.example for environment variables
 */
function parseEnvExample(path: string): { vars: Record<string, string>; hasSecrets: boolean } {
  if (!existsSync(path)) return { vars: {}, hasSecrets: false };

  try {
    const content = readFileSync(path, 'utf-8');
    const vars: Record<string, string> = {};
    let hasSecrets = false;

    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      const match = trimmed.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
      if (match) {
        const key = match[1];
        const value = match[2];
        vars[key] = value;

        // Check for potential secrets
        if (
          key.includes('PASSWORD') ||
          key.includes('SECRET') ||
          key.includes('KEY') ||
          key.includes('TOKEN')
        ) {
          hasSecrets = true;
        }
      }
    }

    return { vars, hasSecrets };
  } catch {
    return { vars: {}, hasSecrets: false };
  }
}

/**
 * Parse package.json to detect framework
 */
function parsePackageJson(path: string): { framework?: string; dependencies: string[] } {
  if (!existsSync(path)) return { dependencies: [] };

  try {
    const content = JSON.parse(readFileSync(path, 'utf-8'));
    const allDeps = {
      ...content.dependencies,
      ...content.devDependencies,
    };

    const dependencies = Object.keys(allDeps);

    // Detect framework
    let framework: string | undefined;
    if (dependencies.includes('express')) framework = 'Express.js';
    else if (dependencies.includes('next')) framework = 'Next.js';
    else if (dependencies.includes('react')) framework = 'React';
    else if (dependencies.includes('vue')) framework = 'Vue.js';
    else if (dependencies.includes('angular')) framework = 'Angular';
    else if (dependencies.includes('fastify')) framework = 'Fastify';
    else if (dependencies.includes('koa')) framework = 'Koa';

    return { framework, dependencies };
  } catch {
    return { dependencies: [] };
  }
}

/**
 * Detect route files and endpoints
 */
function detectRoutes(projectPath: string): Array<{ path: string; methods: string[] }> {
  const routes: Array<{ path: string; methods: string[] }> = [];

  try {
    // Look for common route patterns
    const routePatterns = [
      'routes/**/*.js',
      'routes/**/*.ts',
      'src/routes/**/*.js',
      'src/routes/**/*.ts',
      'api/**/*.js',
      'api/**/*.ts',
    ];

    // Simple file search (production should use glob)
    const searchDirs = ['routes', 'src/routes', 'api', 'src/api'];

    for (const dir of searchDirs) {
      const fullPath = `${projectPath}/${dir}`;
      if (existsSync(fullPath)) {
        const files = readdirSync(fullPath);
        for (const file of files) {
          if (file.endsWith('.js') || file.endsWith('.ts')) {
            // Extract route info from filename
            const routeName = file.replace(/\.(js|ts)$/, '');
            routes.push({
              path: `/${routeName}`,
              methods: ['GET', 'POST', 'PUT', 'DELETE'], // Assume all methods
            });
          }
        }
      }
    }
  } catch {
    // Ignore errors
  }

  return routes;
}

/**
 * Auto-detect components from project
 */
export function detectComponents(projectPath: string, configFiles?: string[]): DetectedComponent[] {
  const components: DetectedComponent[] = [];

  // Parse docker-compose if present
  const dockerComposePaths = configFiles?.filter((f) => f.includes('docker-compose')) || [
    `${projectPath}/docker-compose.yml`,
    `${projectPath}/docker-compose.yaml`,
  ];

  for (const path of dockerComposePaths) {
    components.push(...parseDockerCompose(path));
  }

  // Parse .env.example
  const envPath = `${projectPath}/.env.example`;
  const { vars: envVars, hasSecrets } = parseEnvExample(envPath);

  // Parse package.json
  const packageJsonPath = `${projectPath}/package.json`;
  const { framework, dependencies } = parsePackageJson(packageJsonPath);

  // Add application component if framework detected
  if (framework) {
    const routes = detectRoutes(projectPath);

    components.push({
      name: 'application',
      type: 'api',
      technology: framework,
      routes: routes.length > 0 ? routes : undefined,
      environment: envVars,
      detectedFrom: packageJsonPath,
      confidence: 'high',
    });
  }

  // Detect frontend if React/Vue/Angular present
  if (dependencies.includes('react') || dependencies.includes('vue') || dependencies.includes('angular')) {
    const frontendFramework = dependencies.includes('react')
      ? 'React'
      : dependencies.includes('vue')
      ? 'Vue.js'
      : 'Angular';

    components.push({
      name: 'frontend',
      type: 'frontend',
      technology: frontendFramework,
      detectedFrom: packageJsonPath,
      confidence: 'high',
    });
  }

  return components;
}

/**
 * Get network configuration from components
 */
export function analyzeNetworkTopology(components: DetectedComponent[]): {
  hasNetworkIsolation: boolean;
  sharedNetworks: string[];
  publicPorts: number[];
} {
  const networks = new Set<string>();
  const publicPorts: number[] = [];

  for (const comp of components) {
    if (comp.network) {
      networks.add(comp.network);
    }
    if (comp.ports) {
      publicPorts.push(...comp.ports);
    }
  }

  // Check if all components share default network (no isolation)
  const hasNetworkIsolation = networks.size > 1 || components.every((c) => c.network !== undefined);

  return {
    hasNetworkIsolation,
    sharedNetworks: Array.from(networks),
    publicPorts,
  };
}
