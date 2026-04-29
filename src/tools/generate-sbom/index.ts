/**
 * generate_sbom tool - SBOM generation with license analysis
 */

import { writeFileSync } from 'fs';
import { updateSBOM, requireSession } from '../../session/context';
import { parseProjectPackages } from './package-analyzer';
import { analyzeLicenses } from './license-analyzer';
import { generateCycloneDXJSON, generateCycloneDXXML } from './cyclonedx';
import { generateSPDXJSON } from './spdx';
import { GenerateSBOMArgs, SBOMFormat, SBOMSummary } from './types';

/**
 * generate_sbom tool implementation
 */
export async function generateSBOM(args: any) {
  const { format = 'cyclonedx-json', outputPath, projectPath }: GenerateSBOMArgs = args;

  const session = requireSession();
  const repoPath = projectPath || session.project.path;
  const projectName = session.project.name;

  try {
    // Parse packages from lockfile
    const packages = parseProjectPackages(repoPath);

    if (packages.length === 0) {
      return {
        content: [
          {
            type: 'text',
            text: '⚠️  No packages found in lockfile.',
          },
        ],
      };
    }

    // Analyze licenses
    const { breakdown, issues } = analyzeLicenses(packages);

    // Generate SBOM based on format
    let sbomContent: string;
    let fileExtension: string;

    switch (format) {
      case 'cyclonedx-json':
        sbomContent = generateCycloneDXJSON(packages, projectName);
        fileExtension = 'json';
        break;

      case 'cyclonedx-xml':
        sbomContent = generateCycloneDXXML(packages, projectName);
        fileExtension = 'xml';
        break;

      case 'spdx-json':
        sbomContent = generateSPDXJSON(packages, projectName);
        fileExtension = 'json';
        break;

      default:
        return {
          content: [
            {
              type: 'text',
              text: `❌ Unsupported format: ${format}. Supported: cyclonedx-json, cyclonedx-xml, spdx-json`,
            },
          ],
          isError: true,
        };
    }

    // Write to file if outputPath provided
    let outputFile: string | undefined;
    if (outputPath) {
      outputFile = outputPath;
      writeFileSync(outputFile, sbomContent, 'utf-8');
    } else {
      // Default output path
      outputFile = `${repoPath}/sbom.${fileExtension}`;
      writeFileSync(outputFile, sbomContent, 'utf-8');
    }

    // Build summary
    const directPackages = packages.filter((p) => p.depth === 1);
    const transitivePackages = packages.filter((p) => p.depth > 1);

    const licenseBreakdown = Array.from(breakdown.entries()).map(([license, data]) => ({
      license,
      count: data.count,
      status: data.status,
    }));

    // Sort by count
    licenseBreakdown.sort((a, b) => b.count - a.count);

    const summary: SBOMSummary = {
      totalPackages: packages.length,
      directPackages: directPackages.length,
      transitivePackages: transitivePackages.length,
      licenseBreakdown,
      licenseIssues: issues.map((issue) => ({
        license: issue.license,
        status: issue.status,
        packages: issue.packages,
        reason: issue.reason,
        recommendation: issue.recommendation,
      })),
      eolPackages: [], // Phase 2: implement EOL detection
      unmaintainedPackages: [], // Phase 2: implement GitHub API check
    };

    // Update session - map LicenseAnalysis to LicenseIssue format
    updateSBOM({
      packages,
      licenseIssues: summary.licenseIssues.map((issue) => ({
        license: issue.license,
        reason: issue.reason || '',
        packages: issue.packages,
        severity: issue.status === 'restricted' ? 'high' : 'medium',
        recommendation: issue.recommendation || '',
      })),
      generatedAt: new Date(),
    });

    // Format output
    const output: string[] = [];

    output.push('# Software Bill of Materials (SBOM)');
    output.push('');
    output.push(`📂 Project: ${projectName}`);
    output.push(`📋 Format: ${format}`);
    output.push(`💾 Output: ${outputFile}`);
    output.push('');

    // Summary stats
    output.push('## 📊 Summary');
    output.push('');
    output.push(`- Total packages: ${summary.totalPackages}`);
    output.push(`  - Direct dependencies: ${summary.directPackages}`);
    output.push(`  - Transitive dependencies: ${summary.transitivePackages}`);
    output.push('');

    // License breakdown
    output.push('## 📜 License Breakdown');
    output.push('');

    if (licenseBreakdown.length > 0) {
      const maxLicenseLen = Math.max(...licenseBreakdown.map((l) => l.license.length));

      licenseBreakdown.forEach((item) => {
        const statusEmoji =
          item.status === 'ok' ? '✅' : item.status === 'review' ? '⚠️' : '🛑';
        const paddedLicense = item.license.padEnd(maxLicenseLen);
        output.push(`  ${statusEmoji} ${paddedLicense}  ${item.count} package(s)`);
      });
      output.push('');
    }

    // License issues
    if (summary.licenseIssues.length > 0) {
      output.push('## ⚠️  License Issues');
      output.push('');

      summary.licenseIssues.forEach((issue, i) => {
        const emoji = issue.status === 'restricted' ? '🛑' : '⚠️';
        output.push(`### ${emoji} ${i + 1}. ${issue.license} (${issue.packages.length} packages)`);
        output.push('');
        output.push(`**Reason:** ${issue.reason}`);
        output.push('');
        output.push(`**Recommendation:** ${issue.recommendation}`);
        output.push('');
        output.push(`**Affected packages:**`);
        issue.packages.slice(0, 10).forEach((pkg) => {
          output.push(`  - ${pkg}`);
        });
        if (issue.packages.length > 10) {
          output.push(`  - ... and ${issue.packages.length - 10} more`);
        }
        output.push('');
      });
    } else {
      output.push('✅ No license issues detected - all licenses are permissive or acceptable.');
      output.push('');
    }

    // EOL/Unmaintained (Phase 2 placeholder)
    if (summary.eolPackages.length > 0 || summary.unmaintainedPackages.length > 0) {
      output.push('## ⏰ End-of-Life & Unmaintained Packages');
      output.push('');
      output.push('(EOL detection coming in Phase 2)');
      output.push('');
    }

    // Next steps
    output.push('---');
    output.push('');
    output.push('**💡 Next Steps:**');

    if (summary.licenseIssues.length > 0) {
      const restrictedCount = summary.licenseIssues.filter((i) => i.status === 'restricted').length;
      if (restrictedCount > 0) {
        output.push(`1. 🛑 Review ${restrictedCount} restricted license(s) with legal counsel`);
      }
      const reviewCount = summary.licenseIssues.filter((i) => i.status === 'review').length;
      if (reviewCount > 0) {
        output.push(
          `${restrictedCount > 0 ? '2' : '1'}. ⚠️  Review ${reviewCount} flagged license(s) for compliance`
        );
      }
    }

    output.push('- Share SBOM with security team and compliance');
    output.push('- Include SBOM in release artifacts');
    output.push('- Update SBOM regularly as dependencies change');

    return {
      content: [
        {
          type: 'text',
          text: output.join('\n'),
        },
      ],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: 'text',
          text: `❌ Error generating SBOM: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
}
