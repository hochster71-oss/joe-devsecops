/**
 * J.O.E. DevSecOps Arsenal - Threat Intelligence Service
 * Dark Wolf Solutions
 *
 * Integrates:
 * - EPSS (Exploit Prediction Scoring System) from FIRST.org
 * - CISA KEV (Known Exploited Vulnerabilities) Catalog
 * - NVD (National Vulnerability Database) enrichment
 *
 * References:
 * - EPSS: https://www.first.org/epss
 * - CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
 * - NVD API: https://nvd.nist.gov/developers/vulnerabilities
 */

export interface EPSSScore {
  cve: string;
  epss: number;        // Probability of exploitation (0-1)
  percentile: number;  // Percentile ranking (0-100)
  date: string;
}

export interface KEVEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: 'Known' | 'Unknown';
  notes: string;
}

export interface ThreatIntelResult {
  cve: string;
  epss?: EPSSScore;
  kev?: KEVEntry;
  nvdData?: {
    description: string;
    cvssV3Score: number;
    cvssV3Severity: string;
    cvssV2Score?: number;
    publishedDate: string;
    lastModified: string;
    references: string[];
    cwes: string[];
  };
  priorityScore: number;  // Combined priority (0-100)
  priorityRating: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  recommendation: string;
}

export interface KEVCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KEVEntry[];
}

class ThreatIntelService {
  private kevCache: KEVCatalog | null = null;
  private kevCacheTime: number = 0;
  private epssCache: Map<string, EPSSScore> = new Map();
  private readonly KEV_CACHE_TTL = 6 * 60 * 60 * 1000; // 6 hours
  private readonly EPSS_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

  /**
   * Fetch EPSS score for a CVE
   * Source: FIRST.org EPSS API
   * https://www.first.org/epss/api
   */
  async getEPSSScore(cveId: string): Promise<EPSSScore | null> {
    // Check cache first
    const cached = this.epssCache.get(cveId);
    if (cached) {
      return cached;
    }

    try {
      console.log(`[J.O.E. ThreatIntel] Fetching EPSS score for ${cveId}...`);

      const response = await fetch(
        `https://api.first.org/data/v1/epss?cve=${cveId}`,
        { signal: AbortSignal.timeout(10000) }
      );

      if (!response.ok) {
        throw new Error(`EPSS API error: ${response.status}`);
      }

      const data = await response.json();

      if (data.status === 'OK' && data.data?.length > 0) {
        const epssData = data.data[0];
        const result: EPSSScore = {
          cve: epssData.cve,
          epss: parseFloat(epssData.epss),
          percentile: parseFloat(epssData.percentile) * 100,
          date: epssData.date
        };

        this.epssCache.set(cveId, result);
        console.log(`[J.O.E. ThreatIntel] EPSS for ${cveId}: ${(result.epss * 100).toFixed(2)}% (${result.percentile.toFixed(1)} percentile)`);
        return result;
      }

      return null;
    } catch (error: any) {
      console.error(`[J.O.E. ThreatIntel] EPSS lookup failed for ${cveId}:`, error.message);
      return null;
    }
  }

  /**
   * Fetch multiple EPSS scores in batch
   */
  async getEPSSScoresBatch(cveIds: string[]): Promise<Map<string, EPSSScore>> {
    const results = new Map<string, EPSSScore>();
    const uncached = cveIds.filter(id => !this.epssCache.has(id));

    // Return cached results
    for (const id of cveIds) {
      const cached = this.epssCache.get(id);
      if (cached) results.set(id, cached);
    }

    if (uncached.length === 0) return results;

    try {
      console.log(`[J.O.E. ThreatIntel] Batch fetching EPSS for ${uncached.length} CVEs...`);

      // EPSS API supports batch queries
      const response = await fetch(
        `https://api.first.org/data/v1/epss?cve=${uncached.join(',')}`,
        { signal: AbortSignal.timeout(30000) }
      );

      if (!response.ok) {
        throw new Error(`EPSS API error: ${response.status}`);
      }

      const data = await response.json();

      if (data.status === 'OK' && data.data) {
        for (const epssData of data.data) {
          const result: EPSSScore = {
            cve: epssData.cve,
            epss: parseFloat(epssData.epss),
            percentile: parseFloat(epssData.percentile) * 100,
            date: epssData.date
          };
          this.epssCache.set(epssData.cve, result);
          results.set(epssData.cve, result);
        }
      }

      console.log(`[J.O.E. ThreatIntel] Retrieved EPSS scores for ${results.size} CVEs`);
    } catch (error: any) {
      console.error('[J.O.E. ThreatIntel] Batch EPSS lookup failed:', error.message);
    }

    return results;
  }

  /**
   * Fetch CISA KEV catalog
   * Source: CISA Known Exploited Vulnerabilities Catalog
   * https://www.cisa.gov/known-exploited-vulnerabilities-catalog
   */
  async getKEVCatalog(forceRefresh = false): Promise<KEVCatalog | null> {
    // Check cache
    if (!forceRefresh && this.kevCache && (Date.now() - this.kevCacheTime) < this.KEV_CACHE_TTL) {
      return this.kevCache;
    }

    try {
      console.log('[J.O.E. ThreatIntel] Fetching CISA KEV catalog...');

      const response = await fetch(
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        { signal: AbortSignal.timeout(30000) }
      );

      if (!response.ok) {
        throw new Error(`KEV API error: ${response.status}`);
      }

      const data = await response.json();

      this.kevCache = {
        title: data.title,
        catalogVersion: data.catalogVersion,
        dateReleased: data.dateReleased,
        count: data.count,
        vulnerabilities: data.vulnerabilities
      };
      this.kevCacheTime = Date.now();

      console.log(`[J.O.E. ThreatIntel] KEV catalog loaded: ${this.kevCache.count} vulnerabilities`);
      return this.kevCache;
    } catch (error: any) {
      console.error('[J.O.E. ThreatIntel] KEV catalog fetch failed:', error.message);
      return this.kevCache; // Return stale cache if available
    }
  }

  /**
   * Check if a CVE is in the CISA KEV catalog
   */
  async isInKEV(cveId: string): Promise<KEVEntry | null> {
    const catalog = await this.getKEVCatalog();
    if (!catalog) return null;

    return catalog.vulnerabilities.find(v => v.cveID === cveId) || null;
  }

  /**
   * Get NVD data for a CVE
   */
  async getNVDData(cveId: string): Promise<ThreatIntelResult['nvdData'] | null> {
    try {
      console.log(`[J.O.E. ThreatIntel] Fetching NVD data for ${cveId}...`);

      const response = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
        { signal: AbortSignal.timeout(15000) }
      );

      if (!response.ok) {
        throw new Error(`NVD API error: ${response.status}`);
      }

      const data = await response.json();
      const cve = data.vulnerabilities?.[0]?.cve;

      if (!cve) return null;

      const cvssV3 = cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
                     cve.metrics?.cvssMetricV30?.[0]?.cvssData;
      const cvssV2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;

      return {
        description: cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description available',
        cvssV3Score: cvssV3?.baseScore || 0,
        cvssV3Severity: cvssV3?.baseSeverity || 'UNKNOWN',
        cvssV2Score: cvssV2?.baseScore,
        publishedDate: cve.published,
        lastModified: cve.lastModified,
        references: cve.references?.map((r: any) => r.url) || [],
        cwes: cve.weaknesses?.flatMap((w: any) =>
          w.description?.map((d: any) => d.value)
        ).filter(Boolean) || []
      };
    } catch (error: any) {
      console.error(`[J.O.E. ThreatIntel] NVD lookup failed for ${cveId}:`, error.message);
      return null;
    }
  }

  /**
   * Calculate combined priority score
   * Based on EPSS + KEV + CVSS
   *
   * Priority Algorithm:
   * - KEV presence: +40 points (actively exploited)
   * - EPSS score: 0-30 points (scaled by probability)
   * - CVSS score: 0-30 points (scaled from 0-10)
   */
  calculatePriorityScore(
    epss: EPSSScore | null,
    kev: KEVEntry | null,
    cvssScore: number
  ): { score: number; rating: ThreatIntelResult['priorityRating']; recommendation: string } {
    let score = 0;
    const factors: string[] = [];

    // KEV bonus (highest weight - actively exploited)
    if (kev) {
      score += 40;
      factors.push('In CISA KEV (actively exploited)');

      if (kev.knownRansomwareCampaignUse === 'Known') {
        score += 10; // Extra weight for ransomware
        factors.push('Used in ransomware campaigns');
      }
    }

    // EPSS score (0-30 points)
    if (epss) {
      const epssPoints = Math.min(30, epss.epss * 100 * 3); // Scale 0-1 to 0-30
      score += epssPoints;

      if (epss.epss > 0.1) {
        factors.push(`High exploitation probability (${(epss.epss * 100).toFixed(1)}%)`);
      } else if (epss.epss > 0.01) {
        factors.push(`Moderate exploitation probability (${(epss.epss * 100).toFixed(2)}%)`);
      }
    }

    // CVSS score (0-30 points)
    if (cvssScore > 0) {
      const cvssPoints = (cvssScore / 10) * 30;
      score += cvssPoints;

      if (cvssScore >= 9) {
        factors.push(`Critical CVSS score (${cvssScore})`);
      } else if (cvssScore >= 7) {
        factors.push(`High CVSS score (${cvssScore})`);
      }
    }

    // Determine rating
    let rating: ThreatIntelResult['priorityRating'];
    if (score >= 70 || kev) {
      rating = 'CRITICAL';
    } else if (score >= 50) {
      rating = 'HIGH';
    } else if (score >= 30) {
      rating = 'MEDIUM';
    } else {
      rating = 'LOW';
    }

    // Generate recommendation
    let recommendation: string;
    if (kev) {
      recommendation = `IMMEDIATE ACTION REQUIRED: ${kev.requiredAction}. Due date: ${kev.dueDate}`;
    } else if (rating === 'CRITICAL') {
      recommendation = 'Prioritize remediation immediately. High likelihood of active exploitation.';
    } else if (rating === 'HIGH') {
      recommendation = 'Schedule remediation within 7 days. Elevated risk of exploitation.';
    } else if (rating === 'MEDIUM') {
      recommendation = 'Schedule remediation within 30 days. Monitor for increased threat activity.';
    } else {
      recommendation = 'Schedule remediation in next maintenance window. Low immediate risk.';
    }

    return { score: Math.min(100, Math.round(score)), rating, recommendation };
  }

  /**
   * Get comprehensive threat intelligence for a CVE
   */
  async analyzeCVE(cveId: string): Promise<ThreatIntelResult> {
    console.log(`[J.O.E. ThreatIntel] Analyzing ${cveId}...`);

    // Fetch all data in parallel
    const [epss, kev, nvdData] = await Promise.all([
      this.getEPSSScore(cveId),
      this.isInKEV(cveId),
      this.getNVDData(cveId)
    ]);

    const cvssScore = nvdData?.cvssV3Score || 0;
    const { score, rating, recommendation } = this.calculatePriorityScore(epss, kev, cvssScore);

    return {
      cve: cveId,
      epss: epss || undefined,
      kev: kev || undefined,
      nvdData: nvdData || undefined,
      priorityScore: score,
      priorityRating: rating,
      recommendation
    };
  }

  /**
   * Analyze multiple CVEs and return prioritized list
   */
  async analyzeCVEsBatch(cveIds: string[]): Promise<ThreatIntelResult[]> {
    console.log(`[J.O.E. ThreatIntel] Batch analyzing ${cveIds.length} CVEs...`);

    // Fetch EPSS scores in batch
    const epssScores = await this.getEPSSScoresBatch(cveIds);

    // Load KEV catalog once
    await this.getKEVCatalog();

    // Analyze each CVE
    const results: ThreatIntelResult[] = [];

    for (const cveId of cveIds) {
      const epss = epssScores.get(cveId) || null;
      const kev = await this.isInKEV(cveId);
      const nvdData = await this.getNVDData(cveId);

      const cvssScore = nvdData?.cvssV3Score || 0;
      const { score, rating, recommendation } = this.calculatePriorityScore(epss, kev, cvssScore);

      results.push({
        cve: cveId,
        epss: epss || undefined,
        kev: kev || undefined,
        nvdData: nvdData || undefined,
        priorityScore: score,
        priorityRating: rating,
        recommendation
      });
    }

    // Sort by priority score (highest first)
    results.sort((a, b) => b.priorityScore - a.priorityScore);

    console.log(`[J.O.E. ThreatIntel] Analysis complete. Top priority: ${results[0]?.cve} (score: ${results[0]?.priorityScore})`);
    return results;
  }

  /**
   * Get KEV statistics
   */
  async getKEVStats(): Promise<{
    totalCount: number;
    lastUpdated: string;
    byVendor: Record<string, number>;
    ransomwareRelated: number;
    recentlyAdded: KEVEntry[];
  }> {
    const catalog = await this.getKEVCatalog();

    if (!catalog) {
      return {
        totalCount: 0,
        lastUpdated: 'Unknown',
        byVendor: {},
        ransomwareRelated: 0,
        recentlyAdded: []
      };
    }

    const byVendor: Record<string, number> = {};
    let ransomwareRelated = 0;

    for (const vuln of catalog.vulnerabilities) {
      byVendor[vuln.vendorProject] = (byVendor[vuln.vendorProject] || 0) + 1;
      if (vuln.knownRansomwareCampaignUse === 'Known') {
        ransomwareRelated++;
      }
    }

    // Get recently added (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const recentlyAdded = catalog.vulnerabilities
      .filter(v => new Date(v.dateAdded) >= thirtyDaysAgo)
      .sort((a, b) => new Date(b.dateAdded).getTime() - new Date(a.dateAdded).getTime())
      .slice(0, 10);

    return {
      totalCount: catalog.count,
      lastUpdated: catalog.dateReleased,
      byVendor,
      ransomwareRelated,
      recentlyAdded
    };
  }

  /**
   * Search KEV catalog
   */
  async searchKEV(query: string): Promise<KEVEntry[]> {
    const catalog = await this.getKEVCatalog();
    if (!catalog) return [];

    const lowerQuery = query.toLowerCase();
    return catalog.vulnerabilities.filter(v =>
      v.cveID.toLowerCase().includes(lowerQuery) ||
      v.vendorProject.toLowerCase().includes(lowerQuery) ||
      v.product.toLowerCase().includes(lowerQuery) ||
      v.vulnerabilityName.toLowerCase().includes(lowerQuery) ||
      v.shortDescription.toLowerCase().includes(lowerQuery)
    );
  }

  /**
   * Clear caches
   */
  clearCache(): void {
    this.kevCache = null;
    this.kevCacheTime = 0;
    this.epssCache.clear();
    console.log('[J.O.E. ThreatIntel] Cache cleared');
  }
}

// Export singleton instance
export const threatIntelService = new ThreatIntelService();
export default ThreatIntelService;
