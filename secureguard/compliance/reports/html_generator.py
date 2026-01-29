"""HTML report generator for compliance reports."""

from typing import Any, Dict
from datetime import datetime

from secureguard.compliance.reports.base import BaseReportGenerator
from secureguard.compliance.core.evidence import ComplianceReport


class HTMLReportGenerator(BaseReportGenerator):
    """Generate HTML format compliance reports."""

    def generate(self, compliance_result: ComplianceReport, **kwargs) -> str:
        """Generate HTML compliance report.

        Args:
            compliance_result: Compliance report data
            **kwargs: Additional options:
                - title: Custom report title
                - include_findings_details: Include detailed findings (default: True)

        Returns:
            HTML formatted report string
        """
        data = self._prepare_data(compliance_result)

        title = kwargs.get("title", f"{data['framework']['name']} Compliance Report")
        include_findings = kwargs.get("include_findings_details", True)

        html = self._build_html(data, title, include_findings)

        return html

    def _build_html(self, data: Dict[str, Any], title: str, include_findings: bool) -> str:
        """Build HTML report.

        Args:
            data: Report data
            title: Report title
            include_findings: Whether to include detailed findings

        Returns:
            HTML string
        """
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        {self._get_styles()}
    </style>
</head>
<body>
    <div class="container">
        {self._build_header(data, title)}
        {self._build_executive_summary(data)}
        {self._build_score_section(data)}
        {self._build_summary_stats(data)}
        {self._build_recommendations(data)}
        {self._build_gaps_section(data, include_findings)}
        {self._build_footer(data)}
    </div>
</body>
</html>"""

        return html

    def _get_styles(self) -> str:
        """Get CSS styles for the report."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
        }

        header {
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }

        h1 {
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        h2 {
            color: #34495e;
            font-size: 1.8em;
            margin-top: 30px;
            margin-bottom: 15px;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }

        h3 {
            color: #34495e;
            font-size: 1.3em;
            margin-top: 20px;
            margin-bottom: 10px;
        }

        .meta-info {
            color: #7f8c8d;
            font-size: 0.95em;
        }

        .score-container {
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 30px 0;
        }

        .score-circle {
            width: 200px;
            height: 200px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            font-size: 3em;
            font-weight: bold;
            color: white;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .score-label {
            font-size: 0.4em;
            font-weight: normal;
            margin-top: 5px;
        }

        .status-compliant {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }

        .status-partial {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }

        .status-non_compliant {
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }

        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }

        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }

        .stat-label {
            color: #7f8c8d;
            font-size: 0.9em;
            margin-top: 5px;
        }

        .recommendations {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px 20px;
            margin: 20px 0;
            border-radius: 4px;
        }

        .recommendations ul {
            margin-left: 20px;
            margin-top: 10px;
        }

        .recommendations li {
            margin: 5px 0;
        }

        .control-card {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin: 20px 0;
            overflow: hidden;
        }

        .control-header {
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }

        .control-header:hover {
            background: #f8f9fa;
        }

        .control-title {
            flex: 1;
        }

        .control-id {
            font-weight: bold;
            color: #2c3e50;
        }

        .status-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
            text-transform: uppercase;
        }

        .status-badge.compliant {
            background-color: #28a745;
        }

        .status-badge.partial {
            background-color: #ffc107;
            color: #333;
        }

        .status-badge.non_compliant {
            background-color: #dc3545;
        }

        .status-badge.not_tested {
            background-color: #6c757d;
        }

        .control-body {
            padding: 20px;
            border-top: 1px solid #dee2e6;
            background: #f8f9fa;
        }

        .control-meta {
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }

        .meta-item {
            font-size: 0.9em;
        }

        .meta-label {
            font-weight: bold;
            color: #7f8c8d;
        }

        .coverage-bar {
            width: 100%;
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }

        .coverage-fill {
            height: 100%;
            background: linear-gradient(90deg, #28a745, #20c997);
            transition: width 0.3s ease;
        }

        .findings-section {
            margin-top: 15px;
        }

        .finding {
            background: white;
            border-left: 3px solid #dc3545;
            padding: 10px 15px;
            margin: 10px 0;
            border-radius: 4px;
        }

        .finding-severity {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            margin-right: 10px;
        }

        .severity-CRITICAL {
            background-color: #721c24;
            color: white;
        }

        .severity-HIGH {
            background-color: #dc3545;
            color: white;
        }

        .severity-MEDIUM {
            background-color: #ffc107;
            color: #333;
        }

        .severity-LOW {
            background-color: #17a2b8;
            color: white;
        }

        footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }

        @media print {
            body {
                background-color: white;
            }

            .control-card {
                page-break-inside: avoid;
            }
        }
        """

    def _build_header(self, data: Dict[str, Any], title: str) -> str:
        """Build report header."""
        return f"""
        <header>
            <h1>{title}</h1>
            <div class="meta-info">
                <p><strong>Framework:</strong> {data['framework']['name']} (Version {data['framework']['version']})</p>
                <p><strong>Scan Date:</strong> {data['scan_date']}</p>
                <p><strong>Overall Status:</strong> {data['overall_status'].replace('_', ' ').title()}</p>
            </div>
        </header>
        """

    def _build_executive_summary(self, data: Dict[str, Any]) -> str:
        """Build executive summary section."""
        summary = data['summary']
        total = summary.get('total', 0)

        return f"""
        <section class="executive-summary">
            <h2>Executive Summary</h2>
            <p>This compliance assessment evaluated {total} controls from the {data['framework']['name']} framework.
            The overall compliance score is {data['overall_score']}%.</p>
        </section>
        """

    def _build_score_section(self, data: Dict[str, Any]) -> str:
        """Build score visualization section."""
        score = data['overall_score']
        status = data['overall_status']

        status_class = f"status-{status}"

        return f"""
        <section class="score-section">
            <div class="score-container">
                <div class="score-circle {status_class}">
                    <div>{score}%</div>
                    <div class="score-label">Compliance Score</div>
                </div>
            </div>
        </section>
        """

    def _build_summary_stats(self, data: Dict[str, Any]) -> str:
        """Build summary statistics section."""
        stats = data['stats']
        summary = data['summary']

        return f"""
        <section class="summary-stats">
            <h2>Summary Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{stats['total_controls']}</div>
                    <div class="stat-label">Total Controls</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #28a745;">{summary.get('compliant', 0)}</div>
                    <div class="stat-label">Compliant</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #ffc107;">{summary.get('partial', 0)}</div>
                    <div class="stat-label">Partial</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #dc3545;">{summary.get('non_compliant', 0)}</div>
                    <div class="stat-label">Non-Compliant</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['total_findings']}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['compliance_rate']}%</div>
                    <div class="stat-label">Compliance Rate</div>
                </div>
            </div>
        </section>
        """

    def _build_recommendations(self, data: Dict[str, Any]) -> str:
        """Build recommendations section."""
        recommendations = data['recommendations']

        if not recommendations:
            return ""

        recs_html = "\n".join([f"<li>{rec}</li>" for rec in recommendations])

        return f"""
        <section class="recommendations-section">
            <div class="recommendations">
                <h3>Top Recommendations</h3>
                <ul>
                    {recs_html}
                </ul>
            </div>
        </section>
        """

    def _build_gaps_section(self, data: Dict[str, Any], include_findings: bool) -> str:
        """Build gaps analysis section."""
        gaps = data['gaps']

        # Group by status
        non_compliant = [g for g in gaps if g['status'] == 'non_compliant']
        partial = [g for g in gaps if g['status'] == 'partial']
        compliant = [g for g in gaps if g['status'] == 'compliant']

        html = '<section class="gaps-section"><h2>Control Details</h2>'

        if non_compliant:
            html += '<h3 style="color: #dc3545;">Non-Compliant Controls</h3>'
            for gap in non_compliant:
                html += self._build_control_card(gap, include_findings)

        if partial:
            html += '<h3 style="color: #ffc107;">Partially Compliant Controls</h3>'
            for gap in partial:
                html += self._build_control_card(gap, include_findings)

        if compliant:
            html += '<h3 style="color: #28a745;">Compliant Controls</h3>'
            for gap in compliant:
                html += self._build_control_card(gap, include_findings)

        html += '</section>'
        return html

    def _build_control_card(self, gap: Dict[str, Any], include_findings: bool) -> str:
        """Build individual control card."""
        control_id = gap['control_id']
        title = gap['control_title']
        status = gap['status']
        coverage = gap['coverage']
        findings_count = gap['findings_count']

        card_html = f"""
        <div class="control-card">
            <div class="control-header">
                <div class="control-title">
                    <div class="control-id">{control_id}</div>
                    <div>{title}</div>
                </div>
                <span class="status-badge {status}">{status.replace('_', ' ')}</span>
            </div>
            <div class="control-body">
                <div class="control-meta">
                    <div class="meta-item">
                        <span class="meta-label">Category:</span> {gap['category']}
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Severity:</span> {gap['severity']}
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Priority:</span> {gap['priority']}
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Risk Level:</span> {gap['risk_level']}
                    </div>
                </div>

                <div>
                    <strong>Coverage: {coverage}%</strong>
                    <div class="coverage-bar">
                        <div class="coverage-fill" style="width: {coverage}%;"></div>
                    </div>
                </div>

                <p><strong>Description:</strong> {gap['control_description']}</p>
        """

        if gap['recommendations']:
            recs = "\n".join([f"<li>{rec}</li>" for rec in gap['recommendations'][:5]])
            card_html += f"""
                <div style="margin-top: 15px;">
                    <strong>Recommendations:</strong>
                    <ul>{recs}</ul>
                </div>
            """

        if include_findings and findings_count > 0:
            card_html += f"""
                <div class="findings-section">
                    <strong>Findings ({findings_count}):</strong>
            """
            for finding in gap['findings'][:10]:  # Limit to 10 findings
                severity = finding.get('severity', 'MEDIUM')
                description = finding.get('description', 'No description')
                resource = finding.get('resource', finding.get('file', 'N/A'))

                card_html += f"""
                    <div class="finding">
                        <span class="finding-severity severity-{severity}">{severity}</span>
                        <strong>{resource}</strong>
                        <p>{description}</p>
                    </div>
                """
            card_html += '</div>'

        card_html += '</div></div>'
        return card_html

    def _build_footer(self, data: Dict[str, Any]) -> str:
        """Build report footer."""
        return f"""
        <footer>
            <p>Generated by SecureGuard Compliance Automation</p>
            <p>Report generated on {data['scan_date']}</p>
        </footer>
        """
