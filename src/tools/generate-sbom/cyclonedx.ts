/**
 * CycloneDX SBOM generator
 */

import { PackageInfo } from './types';

/**
 * Generate CycloneDX 1.5 JSON SBOM
 */
export function generateCycloneDXJSON(
  packages: PackageInfo[],
  projectName: string,
  projectVersion: string = '1.0.0'
): string {
  const components = packages.map((pkg) => ({
    type: 'library',
    'bom-ref': `pkg:${pkg.ecosystem}/${pkg.name}@${pkg.version}`,
    name: pkg.name,
    version: pkg.version,
    description: pkg.description,
    licenses: pkg.license
      ? [
          {
            license: {
              id: pkg.license,
            },
          },
        ]
      : undefined,
    purl: `pkg:${pkg.ecosystem}/${pkg.name}@${pkg.version}`,
    externalReferences: [
      pkg.homepage
        ? {
            type: 'website',
            url: pkg.homepage,
          }
        : null,
      pkg.repository
        ? {
            type: 'vcs',
            url: pkg.repository,
          }
        : null,
    ].filter(Boolean),
    properties: [
      {
        name: 'cdx:npm:package:depth',
        value: pkg.depth.toString(),
      },
    ],
  }));

  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${generateUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'SecureDev MCP',
          name: 'generate_sbom',
          version: '0.1.0',
        },
      ],
      component: {
        type: 'application',
        name: projectName,
        version: projectVersion,
      },
    },
    components,
  };

  return JSON.stringify(sbom, null, 2);
}

/**
 * Generate CycloneDX 1.5 XML SBOM
 */
export function generateCycloneDXXML(
  packages: PackageInfo[],
  projectName: string,
  projectVersion: string = '1.0.0'
): string {
  const components = packages
    .map((pkg) => {
      const licenses = pkg.license
        ? `
      <licenses>
        <license>
          <id>${escapeXML(pkg.license)}</id>
        </license>
      </licenses>`
        : '';

      const externalRefs = [
        pkg.homepage ? `<reference type="website"><url>${escapeXML(pkg.homepage)}</url></reference>` : '',
        pkg.repository ? `<reference type="vcs"><url>${escapeXML(pkg.repository)}</url></reference>` : '',
      ]
        .filter(Boolean)
        .join('\n        ');

      const externalRefsBlock = externalRefs
        ? `
      <externalReferences>
        ${externalRefs}
      </externalReferences>`
        : '';

      return `
    <component type="library" bom-ref="pkg:${pkg.ecosystem}/${pkg.name}@${pkg.version}">
      <name>${escapeXML(pkg.name)}</name>
      <version>${escapeXML(pkg.version)}</version>
      ${pkg.description ? `<description>${escapeXML(pkg.description)}</description>` : ''}${licenses}
      <purl>pkg:${pkg.ecosystem}/${pkg.name}@${pkg.version}</purl>${externalRefsBlock}
    </component>`;
    })
    .join('');

  return `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" serialNumber="urn:uuid:${generateUUID()}" version="1">
  <metadata>
    <timestamp>${new Date().toISOString()}</timestamp>
    <tools>
      <tool>
        <vendor>SecureDev MCP</vendor>
        <name>generate_sbom</name>
        <version>0.1.0</version>
      </tool>
    </tools>
    <component type="application">
      <name>${escapeXML(projectName)}</name>
      <version>${escapeXML(projectVersion)}</version>
    </component>
  </metadata>
  <components>${components}
  </components>
</bom>`;
}

/**
 * Simple UUID generator (v4)
 */
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Escape XML special characters
 */
function escapeXML(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}
