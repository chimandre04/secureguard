"""Gap analyzer for compliance assessment."""

from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

from secureguard.compliance.core.framework import Framework
from secureguard.compliance.core.control import Control
from secureguard.compliance.core.mapper import ComplianceMapper
from secureguard.compliance.core.evidence import (
    GapAnalysisResult,
    ComplianceReport,
    AuditTrail,
    Evidence
)
from secureguard.utils.severity import Severity


class GapAnalyzer:
    """Analyzes compliance gaps based on security findings.

    The gap analyzer evaluates security findings against compliance
    controls to determine compliance status and coverage.
    """

    def __init__(self, framework: Framework, mapper: Optional[ComplianceMapper] = None):
        """Initialize the gap analyzer.

        Args:
            framework: The compliance framework
            mapper: Optional compliance mapper (created if not provided)
        """
        self.framework = framework
        self.mapper = mapper or ComplianceMapper(framework)

    def analyze(self, findings: List[Dict[str, Any]]) -> ComplianceReport:
        """Perform comprehensive gap analysis.

        Args:
            findings: List of security findings from all scanners

        Returns:
            Complete compliance report with gap analysis
        """
        # Map findings to controls
        mapped_findings = self.mapper.map_findings(findings)

        # Analyze each control
        gaps = []
        for control in self.framework.get_all_controls():
            control_findings = mapped_findings.get(control.id, [])
            gap = self._analyze_control(control, control_findings, findings)
            gaps.append(gap)

        # Calculate overall score and status
        overall_score = self._calculate_overall_score(gaps)
        overall_status = self._determine_overall_status(overall_score, gaps)

        # Create compliance report
        report = ComplianceReport(
            framework=self.framework,
            scan_timestamp=datetime.now(),
            overall_status=overall_status,
            overall_score=overall_score,
            gaps=gaps
        )

        # Calculate summary
        report.calculate_summary()

        return report

    def _analyze_control(
        self,
        control: Control,
        control_findings: List[Dict[str, Any]],
        all_findings: List[Dict[str, Any]]
    ) -> GapAnalysisResult:
        """Analyze a single control for compliance gaps.

        Args:
            control: The compliance control
            control_findings: Findings mapped to this control
            all_findings: All findings (for context)

        Returns:
            Gap analysis result for this control
        """
        # Get total weighted checks for this control
        total_weight = sum(check.weight for check in control.mapped_checks)

        if total_weight == 0:
            # Control has no mapped checks - mark as not tested
            return GapAnalysisResult(
                control=control,
                status="not_tested",
                coverage=0.0,
                findings=[],
                missing_evidence=["No automated checks available for this control"],
                recommendations=["Manual review required"],
                risk_level=control.severity
            )

        # Calculate passing weight (checks with no findings)
        passing_weight = 0.0
        finding_check_ids = set()

        # Collect check IDs from findings
        for finding in control_findings:
            check_id = self.mapper._extract_check_id(finding)
            if check_id:
                finding_check_ids.add(check_id)

        # Calculate weight of passing checks
        for mapped_check in control.mapped_checks:
            if mapped_check.check_id not in finding_check_ids:
                passing_weight += mapped_check.weight

        # Calculate coverage percentage
        coverage = (passing_weight / total_weight) * 100 if total_weight > 0 else 0

        # Determine status based on coverage
        status = self._determine_status(coverage)

        # Generate recommendations
        recommendations = self._generate_recommendations(control, control_findings, status)

        # Determine risk level
        risk_level = self._determine_risk_level(control, status, control_findings)

        return GapAnalysisResult(
            control=control,
            status=status,
            coverage=coverage,
            findings=control_findings,
            missing_evidence=[],
            recommendations=recommendations,
            risk_level=risk_level
        )

    def _determine_status(self, coverage: float) -> str:
        """Determine compliance status based on coverage.

        Args:
            coverage: Coverage percentage (0-100)

        Returns:
            Status string (compliant, partial, non_compliant)
        """
        if coverage >= 95.0:
            return "compliant"
        elif coverage >= 50.0:
            return "partial"
        else:
            return "non_compliant"

    def _generate_recommendations(
        self,
        control: Control,
        findings: List[Dict[str, Any]],
        status: str
    ) -> List[str]:
        """Generate remediation recommendations.

        Args:
            control: The compliance control
            findings: Findings for this control
            status: Compliance status

        Returns:
            List of recommendations
        """
        recommendations = []

        if status == "compliant":
            recommendations.append("Control is compliant. Continue monitoring.")
            return recommendations

        # Group findings by severity
        critical_findings = [f for f in findings if f.get("severity") == "CRITICAL"]
        high_findings = [f for f in findings if f.get("severity") == "HIGH"]

        if critical_findings:
            recommendations.append(
                f"Address {len(critical_findings)} CRITICAL findings immediately"
            )

        if high_findings:
            recommendations.append(
                f"Address {len(high_findings)} HIGH severity findings"
            )

        # Add control-specific guidance
        if control.implementation_guidance:
            recommendations.append(
                "Review implementation guidance for this control"
            )

        # Add finding-specific recommendations
        unique_remediations = set()
        for finding in findings[:5]:  # Limit to top 5
            if "remediation" in finding and finding["remediation"]:
                unique_remediations.add(finding["remediation"])

        recommendations.extend(list(unique_remediations))

        return recommendations[:10]  # Limit to 10 recommendations

    def _determine_risk_level(
        self,
        control: Control,
        status: str,
        findings: List[Dict[str, Any]]
    ) -> Severity:
        """Determine risk level for a control gap.

        Args:
            control: The compliance control
            status: Compliance status
            findings: Findings for this control

        Returns:
            Risk severity level
        """
        if status == "compliant":
            return Severity.INFO

        # Base risk on control severity
        base_risk = control.severity

        # Increase risk if there are critical/high findings
        if findings:
            max_finding_severity = Severity.INFO
            for finding in findings:
                severity_str = finding.get("severity", "INFO")
                try:
                    finding_severity = Severity[severity_str.upper()]
                    if finding_severity > max_finding_severity:
                        max_finding_severity = finding_severity
                except (KeyError, AttributeError):
                    pass

            # Return the higher of control severity or finding severity
            return max(base_risk, max_finding_severity)

        return base_risk

    def _calculate_overall_score(self, gaps: List[GapAnalysisResult]) -> float:
        """Calculate overall compliance score.

        Args:
            gaps: List of gap analysis results

        Returns:
            Overall score (0-100)
        """
        if not gaps:
            return 0.0

        # Weight controls by priority
        total_weighted_score = 0.0
        total_weight = 0.0

        for gap in gaps:
            # Skip not-tested controls
            if gap.status == "not_tested":
                continue

            # Weight by control priority (1=highest, 5=lowest)
            weight = 6 - gap.control.priority  # Invert priority (5=highest weight)

            total_weighted_score += gap.coverage * weight
            total_weight += weight

        if total_weight == 0:
            return 0.0

        return total_weighted_score / total_weight

    def _determine_overall_status(
        self,
        overall_score: float,
        gaps: List[GapAnalysisResult]
    ) -> str:
        """Determine overall compliance status.

        Args:
            overall_score: Overall compliance score
            gaps: List of gap analysis results

        Returns:
            Overall status string
        """
        # Check for any critical non-compliance
        has_critical_gaps = any(
            gap.status == "non_compliant" and
            gap.risk_level == Severity.CRITICAL
            for gap in gaps
        )

        if has_critical_gaps:
            return "non_compliant"

        if overall_score >= 90.0:
            return "compliant"
        elif overall_score >= 60.0:
            return "partial"
        else:
            return "non_compliant"

    def create_audit_trail(
        self,
        findings: List[Dict[str, Any]],
        evidence_list: List[Evidence],
        scan_duration: Optional[float] = None
    ) -> AuditTrail:
        """Create an audit trail for the compliance scan.

        Args:
            findings: List of security findings
            evidence_list: List of evidence items
            scan_duration: Optional scan duration in seconds

        Returns:
            Audit trail object
        """
        return AuditTrail(
            scan_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            framework_id=self.framework.id,
            policy_version="1.0.0",  # TODO: Get from policy
            scanner_version="0.1.0",  # TODO: Get from package version
            findings_count=len(findings),
            evidence_collected=evidence_list,
            scan_metadata={
                "framework_name": self.framework.name,
                "framework_version": self.framework.version,
                "control_count": self.framework.get_control_count(),
            },
            scan_duration=scan_duration
        )

    def get_high_priority_gaps(
        self,
        gaps: List[GapAnalysisResult],
        max_results: int = 10
    ) -> List[GapAnalysisResult]:
        """Get highest priority gaps for remediation.

        Args:
            gaps: List of gap analysis results
            max_results: Maximum number of results to return

        Returns:
            List of high-priority gaps, sorted by priority
        """
        # Filter non-compliant and partial gaps
        priority_gaps = [
            gap for gap in gaps
            if gap.status in ["non_compliant", "partial"]
        ]

        # Sort by risk level (descending) then priority (ascending)
        priority_gaps.sort(
            key=lambda g: (-g.risk_level.value, g.control.priority)
        )

        return priority_gaps[:max_results]

    def get_compliant_controls(self, gaps: List[GapAnalysisResult]) -> List[Control]:
        """Get list of compliant controls.

        Args:
            gaps: List of gap analysis results

        Returns:
            List of compliant controls
        """
        return [gap.control for gap in gaps if gap.status == "compliant"]

    def get_coverage_by_domain(self, gaps: List[GapAnalysisResult]) -> Dict[str, float]:
        """Calculate coverage percentage by domain.

        Args:
            gaps: List of gap analysis results

        Returns:
            Dictionary mapping domain IDs to coverage percentages
        """
        domain_coverage = {}

        for domain in self.framework.domains:
            domain_gaps = [
                gap for gap in gaps
                if gap.control.id in [c.id for c in domain.controls]
            ]

            if not domain_gaps:
                domain_coverage[domain.id] = 0.0
                continue

            avg_coverage = sum(g.coverage for g in domain_gaps) / len(domain_gaps)
            domain_coverage[domain.id] = round(avg_coverage, 2)

        return domain_coverage
