/**
 * Deterministic rule engine for architecture security checks
 */

import { v4 as uuidv4 } from 'uuid';
import { ArchFinding, StrideCategory } from '../../shared/types';
import { calculateInterruptLevel } from '../../shared/interrupt';
import { DetectedComponent } from './types';
import { analyzeNetworkTopology } from './detector';

/**
 * Check for lack of network isolation in Docker setup
 */
function checkNetworkIsolation(components: DetectedComponent[]): ArchFinding | null {
  const { hasNetworkIsolation } = analyzeNetworkTopology(components);

  if (!hasNetworkIsolation && components.length > 1) {
    const severity = 'critical';
    return {
      id: uuidv4(),
      title: 'Missing Network Segmentation',
      description:
        'All services share the default Docker network without explicit isolation. ' +
        'This allows any compromised container to directly access all other services, ' +
        'violating the principle of least privilege and defense in depth.',
      severity,
      interruptLevel: calculateInterruptLevel(severity),
      strideCategory: 'elevation_of_privilege',
      affectedComponents: components.map((c) => c.name),
      nistControl: 'AC-4 (Information Flow Enforcement)',
      mitigations: [
        'Create separate Docker networks for different service tiers (frontend, backend, data)',
        'Use network policies to restrict inter-service communication',
        'Implement service mesh for fine-grained network control',
        'Document and enforce network segmentation in docker-compose.yml',
      ],
      detectionMethod: 'rule',
      metadata: {
        cwe: ['CWE-668'],
        references: [
          'https://owasp.org/www-community/vulnerabilities/Insufficient_Transport_Layer_Protection',
        ],
      },
      toolSource: 'manual',
      foundAt: new Date(),
    };
  }

  return null;
}

/**
 * Check for Redis without authentication
 */
function checkRedisAuth(components: DetectedComponent[]): ArchFinding | null {
  const redisComponents = components.filter(
    (c) => c.type === 'cache' && c.technology?.toLowerCase().includes('redis')
  );

  for (const redis of redisComponents) {
    const hasAuth =
      redis.environment?.REDIS_PASSWORD ||
      redis.environment?.REDIS_AUTH ||
      redis.environment?.['redis.password'];

    if (!hasAuth) {
      const severity = 'high';
      return {
        id: uuidv4(),
        title: 'Redis Cache Without Authentication',
        description:
          `Redis instance "${redis.name}" is running without authentication enabled. ` +
          'Unauthenticated Redis allows any network-accessible client to read, modify, or delete cached data, ' +
          'and potentially execute arbitrary Lua scripts for remote code execution.',
        severity,
        interruptLevel: calculateInterruptLevel(severity),
        strideCategory: 'tampering',
        affectedComponents: [redis.name],
        nistControl: 'IA-2 (Identification and Authentication)',
        mitigations: [
          'Set REDIS_PASSWORD environment variable with a strong password',
          'Configure requirepass directive in redis.conf',
          'Bind Redis to localhost or internal network only',
          'Use Redis ACLs (v6+) for fine-grained access control',
        ],
        detectionMethod: 'rule',
        metadata: {
          cwe: ['CWE-306'],
          references: [
            'https://redis.io/docs/management/security/',
            'https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication',
          ],
        },
        toolSource: 'manual',
        foundAt: new Date(),
      };
    }
  }

  return null;
}

/**
 * Check for shared .env between dev and prod
 */
function checkSharedEnv(components: DetectedComponent[]): ArchFinding | null {
  // Check if .env.example has both DEV and PROD indicators
  const appComponents = components.filter((c) => c.type === 'api' || c.type === 'service');

  for (const comp of appComponents) {
    if (comp.environment) {
      const envKeys = Object.keys(comp.environment);
      const hasDevEnv = envKeys.some((k) => k.includes('DEV') || k.includes('DEVELOPMENT'));
      const hasProdEnv = envKeys.some((k) => k.includes('PROD') || k.includes('PRODUCTION'));

      if (hasDevEnv && hasProdEnv) {
        const severity = 'high';
        return {
          id: uuidv4(),
          title: 'Shared Environment Configuration',
          description:
            'The same .env file appears to be used for both development and production environments. ' +
            'This practice increases the risk of accidentally deploying with incorrect credentials, ' +
            'exposing development secrets in production, or vice versa.',
          severity,
          interruptLevel: calculateInterruptLevel(severity),
          strideCategory: 'information_disclosure',
          affectedComponents: [comp.name],
          nistControl: 'CM-2 (Baseline Configuration)',
          mitigations: [
            'Use separate .env files: .env.development, .env.production',
            'Never commit .env files to version control',
            'Use environment-specific secret management (AWS Secrets Manager, HashiCorp Vault)',
            'Implement deployment pipeline that injects correct env vars per environment',
          ],
          detectionMethod: 'rule',
          metadata: {
            cwe: ['CWE-209'],
          },
          toolSource: 'manual',
          foundAt: new Date(),
        };
      }
    }
  }

  return null;
}

/**
 * Check for admin routes without separation
 */
function checkAdminRouteSeparation(components: DetectedComponent[]): ArchFinding | null {
  const apiComponents = components.filter((c) => c.type === 'api' && c.routes);

  for (const api of apiComponents) {
    const hasAdminRoutes = api.routes?.some((r) => r.path.includes('/admin'));
    const hasPublicRoutes = api.routes?.some(
      (r) => !r.path.includes('/admin') && !r.path.includes('/auth')
    );

    if (hasAdminRoutes && hasPublicRoutes) {
      const severity = 'high';
      return {
        id: uuidv4(),
        title: 'Admin Routes Not Separated',
        description:
          'Administrative endpoints are served from the same application instance as public routes. ' +
          'This increases the attack surface for privilege escalation and makes it harder to apply ' +
          'different security policies (rate limiting, IP allowlisting) to admin functionality.',
        severity,
        interruptLevel: calculateInterruptLevel(severity),
        strideCategory: 'elevation_of_privilege',
        affectedComponents: [api.name],
        nistControl: 'AC-3 (Access Enforcement)',
        mitigations: [
          'Deploy admin API as a separate service with stricter access controls',
          'Use IP allowlisting or VPN for admin endpoints',
          'Implement separate authentication/authorization for admin routes',
          'Consider admin-only subdomain with different security headers',
        ],
        detectionMethod: 'rule',
        metadata: {
          cwe: ['CWE-269'],
          owasp: ['A01:2021'],
        },
        toolSource: 'manual',
        foundAt: new Date(),
      };
    }
  }

  return null;
}

/**
 * Check for HTTP internal traffic
 */
function checkInternalHTTP(components: DetectedComponent[]): ArchFinding | null {
  const httpComponents = components.filter(
    (c) => c.environment && Object.values(c.environment).some((v) => v.includes('http://'))
  );

  if (httpComponents.length > 0) {
    const severity = 'medium';
    return {
      id: uuidv4(),
      title: 'Unencrypted Internal Traffic',
      description:
        'Internal service-to-service communication uses HTTP instead of HTTPS. ' +
        'While internal networks may seem safe, unencrypted traffic can be intercepted ' +
        'by compromised containers or network-level attackers.',
      severity,
      interruptLevel: calculateInterruptLevel(severity),
      strideCategory: 'information_disclosure',
      affectedComponents: httpComponents.map((c) => c.name),
      nistControl: 'SC-8 (Transmission Confidentiality)',
      mitigations: [
        'Use HTTPS for all inter-service communication',
        'Implement mutual TLS (mTLS) between services',
        'Consider service mesh (Istio, Linkerd) for automatic TLS',
        'Use internal CA for service certificates',
      ],
      detectionMethod: 'rule',
      metadata: {
        cwe: ['CWE-319'],
        owasp: ['A02:2021'],
      },
      toolSource: 'manual',
      foundAt: new Date(),
    };
  }

  return null;
}

/**
 * Run all deterministic rules
 */
export function runRules(components: DetectedComponent[]): ArchFinding[] {
  const findings: ArchFinding[] = [];

  const rules = [
    checkNetworkIsolation,
    checkRedisAuth,
    checkSharedEnv,
    checkAdminRouteSeparation,
    checkInternalHTTP,
  ];

  for (const rule of rules) {
    const finding = rule(components);
    if (finding) {
      findings.push(finding);
    }
  }

  return findings;
}
