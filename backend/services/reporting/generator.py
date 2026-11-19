"""
Kali AI - Security Report Generator
Produces clean, structured markdown and JSON security assessment reports.
"""

from __future__ import annotations

from datetime import datetime, timezone
from backend.models.schemas import Assessment
from backend.services.analysis.correlator import FindingCorrelator


class ReportGenerator:
    """Generates structured executive and technical reports for completed assessments."""

    @classmethod
    def generate_markdown(cls, assessment: Assessment) -> str:
        """Render a full technical and executive report in GitHub-flavored Markdown."""
        risk_data = FindingCorrelator.calculate_risk_score(assessment.findings)
        
        md_lines: list[str] = []
        md_lines.append("# KALI AI - CYBERSECURITY ASSESSMENT REPORT")
        md_lines.append(f"**Assessment ID:** `{assessment.id}`  ")
        md_lines.append(f"**Date Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        md_lines.append(f"**Mode:** {'DEMONSTRATION (MOCK)' if assessment.demo_mode else 'ACTIVE AGENT (GEMINI POWERED)'}  ")
        md_lines.append(f"**Overall Risk Rating:** `{risk_data['rating']}` (Risk Score: {risk_data['score']}/100)  ")
        md_lines.append("")

        # 1. Executive Summary
        md_lines.append("## 1. Executive Summary")
        md_lines.append(f"This assessment was conducted with the objective: *\"{assessment.objective}\"*.")
        md_lines.append(f"The automated agent executed **{len(assessment.steps)} operational steps**, resulting in **{len(assessment.findings)} identified findings**.")
        md_lines.append("")
        md_lines.append("| Severity | Count |")
        md_lines.append("| :--- | :--- |")
        for sev, count in risk_data["breakdown"].items():
            md_lines.append(f"| {sev.capitalize()} | {count} |")
        md_lines.append("")

        # 2. Scope & Assessment Plan
        md_lines.append("## 2. Scope & AI Assessment Plan")
        if assessment.plan:
            md_lines.append(f"- **Scope Target:** `{assessment.plan.scope}`")
            md_lines.append(f"- **Objective:** {assessment.plan.objective}")
            if assessment.plan.steps:
                md_lines.append("- **AI Plan Steps:**")
                for s in assessment.plan.steps:
                    md_lines.append(f"  - {s}")
        else:
            md_lines.append("Assessment ran under direct objective classification without pre-staged plan steps.")
        md_lines.append("")

        # 3. Tool Execution & Audit History
        md_lines.append("## 3. Tool Execution & Audit History")
        md_lines.append("| Step | Action | Tool | Status | Execution Time |")
        md_lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for s in assessment.steps:
            tool_name = s.tool_call.tool_id if s.tool_call else "N/A"
            status = "Success" if s.tool_result and s.tool_result.success else ("Failed" if s.tool_result else s.action)
            ex_time = f"{s.tool_result.execution_time}s" if s.tool_result else "0.0s"
            md_lines.append(f"| {s.step_number} | {s.action} | `{tool_name}` | {status} | {ex_time} |")
        md_lines.append("")

        # 4. Detailed Findings
        md_lines.append("## 4. Normalized Security Findings")
        if not assessment.findings:
            md_lines.append("No active vulnerabilities or security warnings were detected during this assessment.")
        else:
            for idx, f in enumerate(assessment.findings, 1):
                md_lines.append(f"### 4.{idx} [{f.severity.value.upper()}] {f.title}")
                md_lines.append(f"- **Finding ID:** `{f.id}`")
                md_lines.append(f"- **Severity:** `{f.severity.value}` | **Confidence:** `{f.confidence.value}` | **Category:** `{f.category}`")
                md_lines.append(f"- **Affected Asset:** `{f.affected_asset}`")
                md_lines.append(f"- **Source Tool:** `{f.source_tool}`")
                md_lines.append(f"- **Description:** {f.description}")
                if f.evidence:
                    md_lines.append("- **Evidence:**")
                    for ev in f.evidence:
                        md_lines.append(f"  - `{ev}`")
                if f.impact:
                    md_lines.append(f"- **Potential Impact:** {f.impact}")
                if f.remediation:
                    md_lines.append(f"- **Recommended Remediation:** {f.remediation}")
                md_lines.append("")

        # 5. Strategic Recommendations
        md_lines.append("## 5. Strategic Remediation Roadmap")
        md_lines.append("1. **Remediate Critical and High-risk items immediately**: Patch identified service vulnerabilities and close unnecessary open administrative interfaces.")
        md_lines.append("2. **Harden Web Configuration**: Add missing HTTP security headers (CSP, X-Frame-Options) and disable verbose server software banners.")
        md_lines.append("3. **Enforce Least Privilege Network Access**: Filter backend database and administration ports from unauthenticated network segments.")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("*Report generated autonomously by Kali AI Security Operator.*")

        return "\n".join(md_lines)
