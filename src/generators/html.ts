// generators/html.ts - Generador de HTML para emails
// Reemplaza a Gemini con lógica determinista y clara

import { ComplianceData, AnalysisResponse, GlobalAnalysisResponse } from '../utils/types';
import { obtenerControlesAfectados, calcularImpactoCertificacion } from '../iso27001/controles';

/**
 * Genera análisis individual de un equipo
 */
export function generarAnalisisIndividual(data: ComplianceData): AnalysisResponse {
  const findings = extraerHallazgos(data);
  const controlesAfectados = obtenerControlesAfectados(findings);
  const impacto = calcularImpactoCertificacion(data.compliance_score, data.errors, controlesAfectados);
  
  // Clasificar hallazgos por criticidad
  const criticos = findings.filter(f => f.criticidad === 'CRITICA');
  const altos = findings.filter(f => f.criticidad === 'ALTA');
  const medios = findings.filter(f => f.criticidad === 'MEDIA');
  
  // Generar resumen ejecutivo
  const resumen = generarResumenEjecutivo(data, criticos, altos, medios);
  
  // Generar riesgos principales
  const riesgos = generarRiesgosPrincipales(criticos, altos);
  
  // Generar acciones recomendadas
  const acciones = generarAccionesRecomendadas(criticos, altos, medios);
  
  return {
    hostname: data.hostname,
    fecha_analisis: new Date().toISOString(),
    score: data.compliance_score,
    resumen_ejecutivo: resumen,
    controles_iso_afectados: controlesAfectados,
    riesgos_principales: riesgos,
    acciones_recomendadas: acciones,
    metricas_cumplimiento: {
      score_actual: data.compliance_score,
      score_objetivo: 90,
      gap_critico: impacto
    }
  };
}

/**
 * Genera reporte HTML consolidado global
 */
export function generarReporteGlobalHTML(
  equipos: ComplianceData[],
  fecha: string
): GlobalAnalysisResponse {
  const totalEquipos = equipos.length;
  const equiposOK = equipos.filter(e => e.errors === 0 && e.warnings === 0).length;
  const equiposWarning = equipos.filter(e => e.errors === 0 && e.warnings > 0).length;
  const equiposCriticos = equipos.filter(e => e.errors > 0).length;
  const scorePromedio = equipos.reduce((sum, e) => sum + e.compliance_score, 0) / totalEquipos;
  
  // Métricas globales
  const metricas = {
    total_equipos: totalEquipos,
    equipos_ok: equiposOK,
    equipos_warning: equiposWarning,
    equipos_criticos: equiposCriticos,
    score_promedio: Math.round(scorePromedio * 10) / 10
  };
  
  // Generar HTML
  const html = `
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Auditoría Hardening ISO 27001 - Reporte Global</title>
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 800px;
      margin: 0 auto;
      padding: 20px;
      background-color: #f5f5f5;
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 30px;
      border-radius: 10px;
      text-align: center;
      margin-bottom: 30px;
    }
    .header h1 {
      margin: 0;
      font-size: 28px;
    }
    .header p {
      margin: 10px 0 0 0;
      opacity: 0.9;
    }
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 15px;
      margin-bottom: 30px;
    }
    .metric-card {
      background: white;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      text-align: center;
    }
    .metric-value {
      font-size: 32px;
      font-weight: bold;
      margin: 10px 0;
    }
    .metric-label {
      color: #666;
      font-size: 14px;
    }
    .status-ok { color: #10b981; }
    .status-warning { color: #f59e0b; }
    .status-critical { color: #ef4444; }
    .section {
      background: white;
      padding: 25px;
      border-radius: 8px;
      margin-bottom: 20px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .section h2 {
      margin-top: 0;
      color: #667eea;
      border-bottom: 2px solid #667eea;
      padding-bottom: 10px;
    }
    .equipment-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 15px;
    }
    .equipment-table th {
      background-color: #f3f4f6;
      padding: 12px;
      text-align: left;
      font-weight: 600;
      border-bottom: 2px solid #e5e7eb;
    }
    .equipment-table td {
      padding: 10px 12px;
      border-bottom: 1px solid #e5e7eb;
    }
    .equipment-table tr:hover {
      background-color: #f9fafb;
    }
    .score-badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 12px;
      font-weight: bold;
      font-size: 14px;
    }
    .score-ok {
      background-color: #d1fae5;
      color: #065f46;
    }
    .score-warning {
      background-color: #fef3c7;
      color: #92400e;
    }
    .score-critical {
      background-color: #fee2e2;
      color: #991b1b;
    }
    .footer {
      text-align: center;
      color: #666;
      margin-top: 30px;
      padding-top: 20px;
      border-top: 1px solid #e5e7eb;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🔒 Auditoría Hardening ISO 27001</h1>
    <p>Reporte Global de Cumplimiento - ${new Date(fecha).toLocaleDateString('es-ES', { 
      weekday: 'long', 
      year: 'numeric', 
      month: 'long', 
      day: 'numeric' 
    })}</p>
  </div>

  <div class="metrics-grid">
    <div class="metric-card">
      <div class="metric-label">Total Equipos</div>
      <div class="metric-value">${metricas.total_equipos}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Score Promedio</div>
      <div class="metric-value status-${metricas.score_promedio >= 90 ? 'ok' : metricas.score_promedio >= 80 ? 'warning' : 'critical'}">
        ${metricas.score_promedio}%
      </div>
    </div>
    <div class="metric-card">
      <div class="metric-label">✅ Equipos OK</div>
      <div class="metric-value status-ok">${metricas.equipos_ok}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">⚠️ Con Warnings</div>
      <div class="metric-value status-warning">${metricas.equipos_warning}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">🚨 Críticos</div>
      <div class="metric-value status-critical">${metricas.equipos_criticos}</div>
    </div>
  </div>

  <div class="section">
    <h2>📊 Resumen de Equipos</h2>
    <table class="equipment-table">
      <thead>
        <tr>
          <th>Hostname</th>
          <th>Score</th>
          <th>Checks</th>
          <th>Warnings</th>
          <th>Errores</th>
          <th>Estado</th>
        </tr>
      </thead>
      <tbody>
        ${equipos.map(eq => `
        <tr>
          <td><strong>${eq.hostname}</strong></td>
          <td><span class="score-badge score-${eq.errors > 0 ? 'critical' : eq.warnings > 0 ? 'warning' : 'ok'}">${eq.compliance_score}%</span></td>
          <td>${eq.total_checks}</td>
          <td>${eq.warnings}</td>
          <td>${eq.errors}</td>
          <td>${eq.errors > 0 ? '🔴' : eq.warnings > 0 ? '🟡' : '🟢'}</td>
        </tr>
        `).join('')}
      </tbody>
    </table>
  </div>

  ${metricas.equipos_criticos > 0 ? `
  <div class="section">
    <h2>🚨 Equipos Que Requieren Atención Inmediata</h2>
    <p>Los siguientes equipos tienen errores críticos que deben resolverse con prioridad:</p>
    <ul>
      ${equipos.filter(e => e.errors > 0).map(e => `
        <li><strong>${e.hostname}</strong>: ${e.errors} error(es) - Score: ${e.compliance_score}%</li>
      `).join('')}
    </ul>
  </div>
  ` : ''}

  <div class="section">
    <h2>📈 Análisis de Cumplimiento</h2>
    <p><strong>Estado general:</strong> ${
      metricas.equipos_criticos > 0 ? 
        `🔴 Se detectaron ${metricas.equipos_criticos} equipo(s) con fallos críticos que requieren atención inmediata.` :
      metricas.score_promedio < 80 ?
        `🟡 El score promedio (${metricas.score_promedio}%) está por debajo del objetivo (90%). Se recomienda plan de remediación.` :
      metricas.score_promedio < 90 ?
        `🟢 Score promedio aceptable (${metricas.score_promedio}%), pero hay margen de mejora para alcanzar el objetivo de 90%.` :
        `✅ Excelente cumplimiento con score promedio de ${metricas.score_promedio}%. Mantener controles actuales.`
    }</p>
    
    <p><strong>Distribución de equipos:</strong></p>
    <ul>
      <li>🟢 Sin problemas: ${metricas.equipos_ok} (${Math.round(metricas.equipos_ok/metricas.total_equipos*100)}%)</li>
      <li>🟡 Con warnings: ${metricas.equipos_warning} (${Math.round(metricas.equipos_warning/metricas.total_equipos*100)}%)</li>
      <li>🔴 Críticos: ${metricas.equipos_criticos} (${Math.round(metricas.equipos_criticos/metricas.total_equipos*100)}%)</li>
    </ul>
  </div>

  <div class="footer">
    <p>🔒 Auditoría Hardening ISO 27001 - Sisteplant IT</p>
    <p>Generado automáticamente por Hardening Analyzer v1.0</p>
  </div>
</body>
</html>
  `.trim();
  
  return { html, metricas };
}

// ========== FUNCIONES AUXILIARES ==========

function extraerHallazgos(data: ComplianceData) {
  const findings: any[] = [];
  
  Object.entries(data.checks).forEach(([seccion, checks]) => {
    Object.entries(checks).forEach(([checkName, checkData]) => {
      if (checkData.estado === 'WARNING' || checkData.estado === 'ERROR') {
        findings.push({
          seccion,
          check_name: checkName,
          estado: checkData.estado,
          criticidad: checkData.criticidad,
          detalle: checkData.detalle
        });
      }
    });
  });
  
  return findings;
}

function generarResumenEjecutivo(
  data: ComplianceData,
  criticos: any[],
  altos: any[],
  medios: any[]
): string {
  const problemas: string[] = [];
  
  if (data.errors > 0) {
    problemas.push(`${data.errors} error(es) crítico(s)`);
  }
  if (data.warnings > 0) {
    problemas.push(`${data.warnings} advertencia(s)`);
  }
  
  if (problemas.length === 0) {
    return `El equipo ${data.hostname} cumple satisfactoriamente con todos los controles de hardening (${data.compliance_score}%). Se recomienda mantener la configuración actual y continuar con auditorías periódicas.`;
  }
  
  return `El equipo ${data.hostname} presenta ${problemas.join(' y ')} en la auditoría de hardening. Score actual: ${data.compliance_score}%. ${
    criticos.length > 0 ? `Se detectaron ${criticos.length} hallazgo(s) de criticidad alta que requieren atención inmediata. ` : ''
  }${
    altos.length > 0 ? `Adicionalmente, hay ${altos.length} hallazgo(s) de prioridad alta que deben resolverse. ` : ''
  }Se requiere plan de remediación.`;
}

function generarRiesgosPrincipales(criticos: any[], altos: any[]): string[] {
  const riesgos: string[] = [];
  
  [...criticos, ...altos].slice(0, 5).forEach(finding => {
    riesgos.push(`${finding.seccion} - ${finding.check_name}: ${finding.detalle}`);
  });
  
  return riesgos;
}

function generarAccionesRecomendadas(criticos: any[], altos: any[], medios: any[]) {
  const acciones: any[] = [];
  
  // Acciones para críticos
  criticos.forEach(f => {
    acciones.push({
      accion: `Resolver: ${f.check_name} - ${f.detalle}`,
      prioridad: 'ALTA' as const,
      plazo: '24 horas'
    });
  });
  
  // Acciones para altos
  altos.slice(0, 3).forEach(f => {
    acciones.push({
      accion: `Corregir: ${f.check_name}`,
      prioridad: 'MEDIA' as const,
      plazo: '1 semana'
    });
  });
  
  return acciones;
}
