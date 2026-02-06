"""
Report Generator - HTML and PDF Reports
"""

import io
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import (
    Application, Category, Check, CheckResult, 
    CheckHistory, TestExecution, CheckAttachment
)


class ReportGenerator:
    """Generate security reports in HTML and PDF formats"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def get_application_data(self, app_id: int) -> Dict[str, Any]:
        """Get complete application data for report"""
        # Get application
        result = await self.session.execute(
            select(Application).where(Application.id == app_id)
        )
        app = result.scalar_one_or_none()
        if not app:
            raise HTTPException(status_code=404, detail="Application not found")
        
        # Get all results with checks
        results_query = await self.session.execute(
            select(CheckResult)
            .options(
                selectinload(CheckResult.check).selectinload(Check.category),
                selectinload(CheckResult.attachments),
                selectinload(CheckResult.history)
            )
            .where(CheckResult.application_id == app_id)
        )
        results = results_query.scalars().all()
        
        # Get test executions
        tests_query = await self.session.execute(
            select(TestExecution)
            .options(selectinload(TestExecution.check))
            .where(TestExecution.application_id == app_id)
            .order_by(TestExecution.executed_at.desc())
            .limit(50)
        )
        tests = tests_query.scalars().all()
        
        return {
            "application": app,
            "results": results,
            "tests": tests
        }
    
    async def generate_summary(self, app_id: int) -> Dict[str, Any]:
        """Generate summary statistics for an application"""
        data = await self.get_application_data(app_id)
        results = data["results"]
        
        # Status counts
        status_counts = {
            "not_started": 0,
            "in_progress": 0,
            "approved": 0,
            "failed": 0,
            "na": 0
        }
        
        # Severity counts for failed
        failed_by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        # Category summary
        categories = {}
        
        for r in results:
            status_counts[r.status] = status_counts.get(r.status, 0) + 1
            
            if r.status == "failed" and r.check:
                sev = r.check.severity or "medium"
                failed_by_severity[sev] = failed_by_severity.get(sev, 0) + 1
            
            if r.check and r.check.category:
                cat_code = r.check.category.code
                if cat_code not in categories:
                    categories[cat_code] = {
                        "code": cat_code,
                        "name": r.check.category.name,
                        "total": 0,
                        "approved": 0,
                        "failed": 0
                    }
                categories[cat_code]["total"] += 1
                if r.status == "approved":
                    categories[cat_code]["approved"] += 1
                elif r.status == "failed":
                    categories[cat_code]["failed"] += 1
        
        return {
            "application": {
                "id": data["application"].id,
                "name": data["application"].name,
                "environment": data["application"].environment,
                "base_url": data["application"].base_url
            },
            "total_checks": len(results),
            "status_counts": status_counts,
            "failed_by_severity": failed_by_severity,
            "category_summary": list(categories.values()),
            "generated_at": datetime.utcnow().isoformat()
        }
    
    async def generate_html_report(
        self, 
        app_id: int,
        report_type: str = "full",
        include_evidence: bool = True,
        include_history: bool = False,
        include_tests: bool = True,
        include_mappings: bool = True,
        include_recommendations: bool = True
    ) -> str:
        """Generate HTML report"""
        data = await self.get_application_data(app_id)
        app = data["application"]
        results = data["results"]
        tests = data["tests"]
        
        # Filter based on report type
        if report_type == "failed":
            results = [r for r in results if r.status == "failed"]
        
        # Calculate stats
        total = len(results)
        approved = sum(1 for r in results if r.status == "approved")
        failed = sum(1 for r in results if r.status == "failed")
        in_progress = sum(1 for r in results if r.status == "in_progress")
        not_started = sum(1 for r in results if r.status == "not_started")
        na = sum(1 for r in results if r.status == "na")
        
        applicable = total - na
        score = round(approved / applicable * 100) if applicable > 0 else 0
        
        # Group by category
        by_category = {}
        for r in results:
            cat_code = r.check.category.code if r.check and r.check.category else "Outros"
            cat_name = r.check.category.name if r.check and r.check.category else "Outros"
            if cat_code not in by_category:
                by_category[cat_code] = {"name": cat_name, "results": []}
            by_category[cat_code]["results"].append(r)
        
        now = datetime.now().strftime("%d/%m/%Y %H:%M")
        
        html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Segurança - {self._escape(app.name)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 40px; text-align: center; }}
        .header h1 {{ font-size: 28px; margin-bottom: 8px; }}
        .header p {{ opacity: 0.8; }}
        .section {{ background: white; margin: 20px 0; padding: 24px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .section h2 {{ color: #1a1a2e; border-bottom: 2px solid #ffd700; padding-bottom: 10px; margin-bottom: 20px; }}
        .section h3 {{ color: #333; margin: 20px 0 10px 0; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }}
        .info-item {{ padding: 12px; background: #f8f9fa; border-radius: 4px; }}
        .info-item label {{ font-size: 12px; color: #666; display: block; }}
        .info-item span {{ font-weight: 600; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; text-align: center; }}
        .stat-box {{ padding: 20px; border-radius: 8px; }}
        .stat-box.total {{ background: #f0f0f0; }}
        .stat-box.approved {{ background: #d4edda; color: #155724; }}
        .stat-box.failed {{ background: #f8d7da; color: #721c24; }}
        .stat-box.progress {{ background: #cce5ff; color: #004085; }}
        .stat-box.score {{ background: #fff3cd; color: #856404; }}
        .stat-value {{ font-size: 32px; font-weight: 700; }}
        .stat-label {{ font-size: 12px; text-transform: uppercase; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
        .badge-success {{ background: #d4edda; color: #155724; }}
        .badge-danger {{ background: #f8d7da; color: #721c24; }}
        .badge-warning {{ background: #fff3cd; color: #856404; }}
        .badge-info {{ background: #cce5ff; color: #004085; }}
        .badge-secondary {{ background: #e9ecef; color: #495057; }}
        .badge-critical {{ background: #721c24; color: white; }}
        .badge-high {{ background: #e74c3c; color: white; }}
        .badge-medium {{ background: #f39c12; color: white; }}
        .badge-low {{ background: #3498db; color: white; }}
        .evidence-box {{ background: #f8f9fa; padding: 12px; border-radius: 4px; margin-top: 8px; font-size: 14px; white-space: pre-wrap; }}
        .recommendation-box {{ background: #fff5f5; padding: 12px; border-left: 4px solid #e74c3c; margin-top: 8px; font-size: 14px; }}
        .mapping {{ display: inline-block; padding: 4px 8px; background: #e9ecef; border-radius: 4px; font-size: 11px; margin-right: 8px; }}
        .category-section {{ margin-top: 24px; }}
        .category-header {{ background: #ffd700; color: #1a1a2e; padding: 12px 16px; font-weight: 600; border-radius: 4px 4px 0 0; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
        @media print {{
            .section {{ break-inside: avoid; }}
            body {{ background: white; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Relatório de Segurança</h1>
        <p>Gerado em {now}</p>
    </div>

    <div class="container">
        <div class="section">
            <h2>Informações da Aplicação</h2>
            <div class="info-grid">
                <div class="info-item">
                    <label>Nome</label>
                    <span>{self._escape(app.name)}</span>
                </div>
                <div class="info-item">
                    <label>Ambiente</label>
                    <span>{app.environment.upper()}</span>
                </div>
                <div class="info-item">
                    <label>URL Base</label>
                    <span>{self._escape(app.base_url)}</span>
                </div>
                <div class="info-item">
                    <label>Responsável</label>
                    <span>{self._escape(app.responsible or 'N/A')}</span>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Resumo Executivo</h2>
            <div class="stats-grid">
                <div class="stat-box total">
                    <div class="stat-value">{total}</div>
                    <div class="stat-label">Total</div>
                </div>
                <div class="stat-box approved">
                    <div class="stat-value">{approved}</div>
                    <div class="stat-label">Aprovados</div>
                </div>
                <div class="stat-box failed">
                    <div class="stat-value">{failed}</div>
                    <div class="stat-label">Reprovados</div>
                </div>
                <div class="stat-box progress">
                    <div class="stat-value">{in_progress}</div>
                    <div class="stat-label">Em Andamento</div>
                </div>
                <div class="stat-box score">
                    <div class="stat-value">{score}%</div>
                    <div class="stat-label">Score</div>
                </div>
            </div>
        </div>
"""
        
        if report_type != "executive":
            html += """
        <div class="section">
            <h2>Resultados Detalhados</h2>
"""
            for cat_code, cat_data in sorted(by_category.items()):
                html += f"""
            <div class="category-section">
                <div class="category-header">{cat_code} - {self._escape(cat_data['name'])}</div>
                <table>
                    <thead>
                        <tr>
                            <th style="width: 100px;">Código</th>
                            <th>Controle</th>
                            <th style="width: 100px;">Severidade</th>
                            <th style="width: 100px;">Status</th>
                        </tr>
                    </thead>
                    <tbody>
"""
                for r in cat_data["results"]:
                    check = r.check
                    severity_class = self._get_severity_class(check.severity if check else "medium")
                    status_class = self._get_status_class(r.status)
                    
                    html += f"""
                        <tr>
                            <td><code>{check.code if check else '-'}</code></td>
                            <td>
                                <strong>{self._escape(check.title if check else '-')}</strong>
"""
                    if include_evidence and r.evidence:
                        html += f"""
                                <div class="evidence-box"><strong>Evidência:</strong> {self._escape(r.evidence)}</div>
"""
                    if include_recommendations and r.status == "failed" and check and check.recommendations:
                        html += f"""
                                <div class="recommendation-box"><strong>Recomendação:</strong> {self._escape(check.recommendations)}</div>
"""
                    if include_mappings and check:
                        if check.mapping_owasp_asvs or check.mapping_owasp_top10 or check.mapping_cwe:
                            html += """<div style="margin-top: 8px;">"""
                            if check.mapping_owasp_asvs:
                                html += f"""<span class="mapping">ASVS: {check.mapping_owasp_asvs}</span>"""
                            if check.mapping_owasp_top10:
                                html += f"""<span class="mapping">Top 10: {check.mapping_owasp_top10}</span>"""
                            if check.mapping_cwe:
                                html += f"""<span class="mapping">CWE: {check.mapping_cwe}</span>"""
                            html += """</div>"""
                    
                    html += f"""
                            </td>
                            <td><span class="badge {severity_class}">{self._get_severity_label(check.severity if check else 'medium')}</span></td>
                            <td><span class="badge {status_class}">{self._get_status_label(r.status)}</span></td>
                        </tr>
"""
                html += """
                    </tbody>
                </table>
            </div>
"""
            html += """
        </div>
"""
        
        # Tests section
        if include_tests and tests:
            html += """
        <div class="section">
            <h2>Resultados de Testes Automatizados</h2>
            <table>
                <thead>
                    <tr>
                        <th>Data/Hora</th>
                        <th>Controle</th>
                        <th>Resultado</th>
                        <th>Duração</th>
                    </tr>
                </thead>
                <tbody>
"""
            for t in tests[:20]:
                result_class = "badge-success" if t.result == "pass" else "badge-danger" if t.result == "fail" else "badge-warning"
                html += f"""
                    <tr>
                        <td>{t.executed_at.strftime('%d/%m/%Y %H:%M') if t.executed_at else '-'}</td>
                        <td><code>{t.check.code if t.check else '-'}</code></td>
                        <td><span class="badge {result_class}">{t.result.upper()}</span></td>
                        <td>{t.duration_ms}ms</td>
                    </tr>
"""
            html += """
                </tbody>
            </table>
        </div>
"""
        
        html += f"""
        <div class="footer">
            <p>Security Checklist - DevSecOps Platform</p>
            <p>Relatório gerado automaticamente em {now}</p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    async def generate_json_report(self, app_id: int, report_type: str = "full") -> Dict[str, Any]:
        """Generate JSON report"""
        data = await self.get_application_data(app_id)
        summary = await self.generate_summary(app_id)
        
        results = data["results"]
        if report_type == "failed":
            results = [r for r in results if r.status == "failed"]
        
        return {
            "generated_at": datetime.utcnow().isoformat(),
            "report_type": report_type,
            "application": {
                "id": data["application"].id,
                "name": data["application"].name,
                "environment": data["application"].environment,
                "base_url": data["application"].base_url,
                "responsible": data["application"].responsible
            },
            "summary": summary,
            "results": [
                {
                    "check_code": r.check.code if r.check else None,
                    "check_title": r.check.title if r.check else None,
                    "category": r.check.category.code if r.check and r.check.category else None,
                    "severity": r.check.severity if r.check else None,
                    "status": r.status,
                    "notes": r.notes,
                    "evidence": r.evidence,
                    "updated_at": r.updated_at.isoformat() if r.updated_at else None
                }
                for r in results
            ]
        }
    
    def _escape(self, text: str) -> str:
        """Escape HTML special characters"""
        if not text:
            return ""
        return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))
    
    def _get_severity_class(self, severity: str) -> str:
        """Get CSS class for severity"""
        classes = {
            "critical": "badge-critical",
            "high": "badge-high",
            "medium": "badge-medium",
            "low": "badge-low",
            "info": "badge-secondary"
        }
        return classes.get(severity, "badge-secondary")
    
    def _get_severity_label(self, severity: str) -> str:
        """Get label for severity"""
        labels = {
            "critical": "Crítico",
            "high": "Alto",
            "medium": "Médio",
            "low": "Baixo",
            "info": "Info"
        }
        return labels.get(severity, severity)
    
    def _get_status_class(self, status: str) -> str:
        """Get CSS class for status"""
        classes = {
            "approved": "badge-success",
            "failed": "badge-danger",
            "in_progress": "badge-info",
            "not_started": "badge-secondary",
            "na": "badge-secondary"
        }
        return classes.get(status, "badge-secondary")
    
    def _get_status_label(self, status: str) -> str:
        """Get label for status"""
        labels = {
            "approved": "Aprovado",
            "failed": "Reprovado",
            "in_progress": "Em Andamento",
            "not_started": "Não Iniciado",
            "na": "N/A"
        }
        return labels.get(status, status)
