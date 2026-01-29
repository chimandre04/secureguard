"""JSON report generator for compliance reports."""

import json
from typing import Any, Dict

from secureguard.compliance.reports.base import BaseReportGenerator
from secureguard.compliance.core.evidence import ComplianceReport


class JSONReportGenerator(BaseReportGenerator):
    """Generate JSON format compliance reports."""

    def generate(self, compliance_result: ComplianceReport, **kwargs) -> str:
        """Generate JSON compliance report.

        Args:
            compliance_result: Compliance report data
            **kwargs: Additional options:
                - indent: JSON indentation (default: 2)
                - sort_keys: Sort dictionary keys (default: False)

        Returns:
            JSON formatted report string
        """
        data = self._prepare_data(compliance_result)

        indent = kwargs.get("indent", 2)
        sort_keys = kwargs.get("sort_keys", False)

        return json.dumps(data, indent=indent, sort_keys=sort_keys, default=str)

    def generate_dict(self, compliance_result: ComplianceReport) -> Dict[str, Any]:
        """Generate compliance report as dictionary.

        Args:
            compliance_result: Compliance report data

        Returns:
            Report data as dictionary
        """
        return self._prepare_data(compliance_result)
