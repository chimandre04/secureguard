"""Base report generator interface."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime

from secureguard.compliance.core.evidence import ComplianceReport, GapAnalysisResult
from secureguard.utils.severity import Severity


class BaseReportGenerator(ABC):
    """Base class for compliance report generators."""

    def __init__(self, template_dir: Optional[Path] = None):
        """Initialize the report generator.

        Args:
            template_dir: Directory containing report templates
        """
        self.template_dir = template_dir or self._default_template_dir()

    def _default_template_dir(self) -> Path:
        """Get the default template directory.

        Returns:
            Path to templates directory
        """
        return Path(__file__).parent / "templates"

    @abstractmethod
    def generate(self, compliance_result: ComplianceReport, **kwargs) -> str:
        """Generate compliance report.

        Args:
            compliance_result: Compliance report data
            **kwargs: Additional generator-specific options

        Returns:
            Generated report as string
        """
        pass

    def _prepare_data(self, result: ComplianceReport) -> Dict[str, Any]:
        """Prepare data for report generation.

        Args:
            result: Compliance report

        Returns:
            Dictionary with prepared data
        """
        return {
            "framework": {
                "id": result.framework.id,
                "name": result.framework.name,
                "version": result.framework.version,
                "description": result.framework.description,
            },
            "scan_date": result.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_timestamp": result.scan_timestamp.isoformat(),
            "overall_score": round(result.overall_score, 2),
            "overall_status": result.overall_status,
            "summary": result.summary,
            "gaps": self._format_gaps(result.gaps),
            "recommendations": self._build_recommendations(result),
            "evidence": result.evidence_trail.to_dict() if result.evidence_trail else None,
            "stats": self._build_stats(result),
        }

    def _format_gaps(self, gaps: List[GapAnalysisResult]) -> List[Dict[str, Any]]:
        """Format gap analysis results.

        Args:
            gaps: List of gap analysis results

        Returns:
            List of formatted gap dictionaries
        """
        formatted_gaps = []

        for gap in gaps:
            formatted_gap = {
                "control_id": gap.control.id,
                "control_title": gap.control.title,
                "control_description": gap.control.description,
                "category": gap.control.category,
                "severity": str(gap.control.severity),
                "priority": gap.control.priority,
                "status": gap.status,
                "coverage": round(gap.coverage, 2),
                "findings_count": len(gap.findings),
                "findings": gap.findings,
                "recommendations": gap.recommendations,
                "risk_level": str(gap.risk_level) if gap.risk_level else "INFO",
                "implementation_guidance": gap.control.implementation_guidance,
            }
            formatted_gaps.append(formatted_gap)

        # Sort by status (non_compliant first) then by priority
        formatted_gaps.sort(
            key=lambda g: (
                {"non_compliant": 0, "partial": 1, "not_tested": 2, "compliant": 3}[g["status"]],
                g["priority"]
            )
        )

        return formatted_gaps

    def _build_recommendations(self, result: ComplianceReport) -> List[str]:
        """Build top-level recommendations.

        Args:
            result: Compliance report

        Returns:
            List of recommendations
        """
        recommendations = []

        # Critical findings
        critical_gaps = [g for g in result.gaps if g.risk_level == Severity.CRITICAL]
        if critical_gaps:
            recommendations.append(
                f"CRITICAL: Address {len(critical_gaps)} critical compliance gaps immediately"
            )

        # Non-compliant controls
        non_compliant = result.get_non_compliant_count()
        if non_compliant > 0:
            recommendations.append(
                f"Remediate {non_compliant} non-compliant controls"
            )

        # Partial controls
        partial = result.get_partial_count()
        if partial > 0:
            recommendations.append(
                f"Improve {partial} partially compliant controls"
            )

        # High priority recommendations from gaps
        high_priority_gaps = sorted(
            [g for g in result.gaps if g.status != "compliant"],
            key=lambda g: (-g.risk_level.value, g.control.priority)
        )[:5]

        for gap in high_priority_gaps:
            if gap.recommendations:
                rec = f"{gap.control.id}: {gap.recommendations[0]}"
                if rec not in recommendations:
                    recommendations.append(rec)

        return recommendations[:15]  # Limit to top 15

    def _build_stats(self, result: ComplianceReport) -> Dict[str, Any]:
        """Build statistics for the report.

        Args:
            result: Compliance report

        Returns:
            Statistics dictionary
        """
        total_controls = len(result.gaps)
        total_findings = sum(len(g.findings) for g in result.gaps)

        return {
            "total_controls": total_controls,
            "total_findings": total_findings,
            "compliant_controls": result.get_compliant_count(),
            "partial_controls": result.get_partial_count(),
            "non_compliant_controls": result.get_non_compliant_count(),
            "not_tested_controls": result.get_not_tested_count(),
            "compliance_rate": round(
                (result.get_compliant_count() / total_controls * 100) if total_controls > 0 else 0,
                2
            ),
        }

    def _get_status_color(self, status: str) -> str:
        """Get color for a status.

        Args:
            status: Status string

        Returns:
            Color code or name
        """
        colors = {
            "compliant": "#28a745",  # green
            "partial": "#ffc107",     # yellow
            "non_compliant": "#dc3545",  # red
            "not_tested": "#6c757d",  # gray
        }
        return colors.get(status, "#6c757d")

    def _get_severity_color(self, severity: str) -> str:
        """Get color for a severity level.

        Args:
            severity: Severity string

        Returns:
            Color code or name
        """
        colors = {
            "CRITICAL": "#721c24",  # dark red
            "HIGH": "#dc3545",      # red
            "MEDIUM": "#ffc107",    # yellow
            "LOW": "#17a2b8",       # blue
            "INFO": "#6c757d",      # gray
        }
        return colors.get(severity.upper(), "#6c757d")
