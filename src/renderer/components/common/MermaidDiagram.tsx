/**
 * J.O.E. Mermaid Diagram Component
 * Renders Mermaid diagrams with Dark Wolf theming
 */

import { useEffect, useRef, useState } from 'react';
import mermaid from 'mermaid';

interface MermaidDiagramProps {
  chart: string;
  id?: string;
  className?: string;
}

// Initialize mermaid with Dark Wolf theme
mermaid.initialize({
  startOnLoad: false,
  theme: 'dark',
  themeVariables: {
    primaryColor: '#00b4d8',
    primaryTextColor: '#00b4d8',
    primaryBorderColor: '#00b4d8',
    lineColor: '#00b4d8',
    secondaryColor: '#0d2137',
    tertiaryColor: '#1a1f2e',
    background: '#0d1117',
    mainBkg: '#0d2137',
    nodeBorder: '#00b4d8',
    clusterBkg: '#1a1f2e',
    clusterBorder: '#00b4d8',
    titleColor: '#00b4d8',
    edgeLabelBackground: '#0d1117',
    nodeTextColor: '#e5e7eb',
    fontFamily: '"Inter", sans-serif'
  },
  flowchart: {
    htmlLabels: true,
    curve: 'basis',
    padding: 20
  },
  securityLevel: 'loose'
});

export default function MermaidDiagram({ chart, id, className = '' }: MermaidDiagramProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [svg, setSvg] = useState<string>('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const renderDiagram = async () => {
      if (!containerRef.current) {return;}

      try {
        const uniqueId = id || `mermaid-${Math.random().toString(36).substr(2, 9)}`;
        const { svg: renderedSvg } = await mermaid.render(uniqueId, chart);
        setSvg(renderedSvg);
        setError(null);
      } catch (err) {
        console.error('Mermaid render error:', err);
        setError(err instanceof Error ? err.message : 'Failed to render diagram');
      }
    };

    renderDiagram();
  }, [chart, id]);

  if (error) {
    return (
      <div className={`p-4 bg-alert-critical/10 border border-alert-critical/30 rounded-lg ${className}`}>
        <p className="text-alert-critical text-sm">Failed to render diagram: {error}</p>
        <pre className="mt-2 text-gray-400 text-xs overflow-x-auto">{chart}</pre>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className={`mermaid-container flex items-center justify-center ${className}`}
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}

// Predefined J.O.E. Architecture Diagrams
export const JOE_ARCHITECTURE_DIAGRAM = `
flowchart TB
    subgraph IP["<b>INTELLIGENCE PLANE</b>"]
        IP_desc["Agents, Models, Predictive Analytics"]
    end

    subgraph CP["<b>CONTROL PLANE</b>"]
        CP_desc["Governance, Risk,<br/>Compliance, Policy"]
    end

    subgraph EP["<b>EXECUTION PLANE</b>"]
        EP_desc["Pipelines, Guardrails,<br/>Enforcement, Fixes"]
    end

    subgraph DP["<b>DATA PLANE</b>"]
        DP_desc["Telemetry, SBOMs, Logs,<br/>Evidence, Metadata, Events"]
    end

    IP <-->|"Intelligence Feed"| CP
    IP <-->|"Action Commands"| EP
    CP <-->|"Policy Enforcement"| EP
    CP <-->|"Compliance Data"| DP
    EP <-->|"Telemetry"| DP
`;

export const JOE_AGENT_FLOW_DIAGRAM = `
flowchart LR
    subgraph Sources["Data Sources"]
        S1[/"Code Repos"/]
        S2[/"Container Images"/]
        S3[/"Infrastructure"/]
        S4[/"Runtime Logs"/]
    end

    subgraph Agents["J.O.E. Agents"]
        A1["Build Agent"]
        A2["Security Agent"]
        A3["Governance Agent"]
        A4["Runtime Defense"]
    end

    subgraph Actions["Control Actions"]
        C1(["Block/Allow"])
        C2(["Alert"])
        C3(["Remediate"])
        C4(["Report"])
    end

    S1 --> A1
    S2 --> A2
    S3 --> A3
    S4 --> A4

    A1 --> C1
    A2 --> C2
    A3 --> C3
    A4 --> C4
`;

export const JOE_THREAT_INTEL_FLOW = `
flowchart TD
    subgraph External["External Intelligence"]
        EPSS["EPSS<br/>FIRST.org"]
        KEV["CISA KEV<br/>Catalog"]
        NVD["NVD<br/>Database"]
    end

    subgraph JOE["J.O.E. Processing"]
        Ingest["Data Ingestion"]
        Enrich["CVE Enrichment"]
        Score["Priority Scoring"]
        Cache["Intel Cache"]
    end

    subgraph Output["Actionable Intelligence"]
        Priority["Priority Rating"]
        Recommend["Recommendations"]
        Alert["Alert Generation"]
    end

    EPSS --> Ingest
    KEV --> Ingest
    NVD --> Ingest

    Ingest --> Enrich
    Enrich --> Score
    Score --> Cache

    Cache --> Priority
    Cache --> Recommend
    Cache --> Alert
`;
