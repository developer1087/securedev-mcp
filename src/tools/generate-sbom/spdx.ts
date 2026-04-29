/**
 * SPDX SBOM generator
 */

import { PackageInfo } from './types';

/**
 * Generate SPDX 2.3 JSON SBOM
 */
export function generateSPDXJSON(
  packages: PackageInfo[],
  projectName: string,
  projectVersion: string = '1.0.0'
): string {
  const documentNamespace = `https://sbom.securedev-mcp/${projectName}/${generateUUID()}`;

  const packageData = packages.map((pkg, index) => ({
    SPDXID: `SPDXRef-Package-${index + 1}`,
    name: pkg.name,
    versionInfo: pkg.version,
    downloadLocation: pkg.repository || 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: pkg.license || 'NOASSERTION',
    licenseDeclared: pkg.license || 'NOASSERTION',
    copyrightText: pkg.author || 'NOASSERTION',
    externalRefs: [
      pkg.repository
        ? {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: `pkg:${pkg.ecosystem}/${pkg.name}@${pkg.version}`,
          }
        : null,
    ].filter(Boolean),
  }));

  const relationships = packages.map((_, index) => ({
    spdxElementId: 'SPDXRef-DOCUMENT',
    relationshipType: 'DESCRIBES',
    relatedSpdxElement: `SPDXRef-Package-${index + 1}`,
  }));

  const sbom = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${projectName}-SBOM`,
    documentNamespace,
    creationInfo: {
      created: new Date().toISOString(),
      creators: ['Tool: SecureDev MCP generate_sbom-0.1.0'],
      licenseListVersion: '3.21',
    },
    packages: [
      {
        SPDXID: 'SPDXRef-Package-0',
        name: projectName,
        versionInfo: projectVersion,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'NOASSERTION',
        copyrightText: 'NOASSERTION',
      },
      ...packageData,
    ],
    relationships,
  };

  return JSON.stringify(sbom, null, 2);
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
