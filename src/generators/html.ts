// generators/html.ts - Generador de análisis completo
// Versión 3.1 - Compatible con workflow N8N v5 FINAL
// Genera la misma estructura que esperaba Gemini IA

import { ComplianceData, AnalysisResponse, GlobalAnalysisResponse } from '../utils/types';
import { obtenerControlesAfectados, calcularImpactoCertificacion, MAPEO_VERIFICACIONES_ISO, CONTROLES_ISO27001 } from '../iso27001/controles';

// ============================================================
// ANÁLISIS INDIVIDUAL (reemplaza Gemini individual)
// Devuelve estructura idéntica a la que esperaba el nodo N8N
// ============================================================
export function generarAnalisisIndividual(data: ComplianceData): AnalysisResponse {
  const findings = extraerHallazgos(data);
  const controlesAfectados = obtenerControlesAfectados(findings);
  const impactoCertificacion = calcularImpactoCertificacion(data.compliance_score, data.errors || 0, controlesAfectados);

  // Clasificar hallazgos por criticidad
  const criticos = findings.filter(f => f.criticidad === 'CRITICA' || f.criticidad === 'ALTA');
  const medios = findings.filter(f => f.criticidad === 'MEDIA');
  const bajos = findings.filter(f => f.criticidad === 'BAJA');

  const score = data.compliance_score;
  const errores = data.errors || 0;
  const warnings = data.warnings || 0;

  // === RESUMEN EJECUTIVO ===
  const resumen = generarResumenEjecutivo(data, findings);

  // === MAPEO ISO 27001 ===
  const mapeoISO = generarMapeoISO(findings, controlesAfectados, impactoCertificacion, score, errores);

  // === RIESGOS (3) ===
  const riesgos = generarRiesgos(data, findings, criticos);

  // === ACCIONES (5) ===
  const acciones = generarAcciones(data, findings, criticos, medios);

  // === MÉTRICAS ===
  const gapPuntos = 90 - score;
  const tiempoRemediacion = errores > 0 ? '2-5 días' : gapPuntos > 20 ? '1-2 semanas' : '3-5 días';

  // === SEGUIMIENTO ===
  const diasRevision = errores > 0 ? 7 : score < 80 ? 14 : 30;
  const fechaRevision = new Date(Date.now() + diasRevision * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  const tendencia = score >= 90 ? 'MEJORA' : score >= 80 ? 'ESTABLE' : 'DETERIORO';

  return {
    hostname: data.hostname,
    fecha_analisis: new Date().toISOString(),
    compliance_score: score,
    score: score,
    resumen_ejecutivo: resumen,
    mapeo_iso27001: mapeoISO,
    riesgos: riesgos,
    acciones_recomendadas: acciones,
    metricas_cumplimiento: {
      score_actual: score,
      score_objetivo: 90,
      gap_critico: gapPuntos > 0
        ? `${gapPuntos} puntos por debajo del objetivo. Causas: ${criticos.slice(0, 3).map(f => f.check_name).join(', ') || 'sin hallazgos críticos'}`
        : 'Objetivo alcanzado',
      tiempo_remediacion_estimado: tiempoRemediacion,
      controles_ok: data.passed || 0,
      controles_fallo: errores + warnings
    },
    seguimiento: {
      proxima_revision: fechaRevision,
      indicadores_clave: [
        `Score de cumplimiento (actual: ${score}%, objetivo: 90%)`,
        `Errores críticos: ${errores}`,
        `Warnings: ${warnings}`,
        ...(data.sistema_operativo?.soporte_activo === false ? ['Estado soporte SO: CRÍTICO'] : [])
      ].slice(0, 4),
      tendencia: tendencia,
      comentarios: generarComentariosSeguimiento(data, findings)
    }
  };
}

// ============================================================
// REPORTE GLOBAL HTML (reemplaza Gemini global)
// Genera email HTML detallado con análisis completo
// ============================================================
export function generarReporteGlobalHTML(
  equipos: ComplianceData[],
  fecha: string
): GlobalAnalysisResponse {
  const totalEquipos = equipos.length;
  const equiposOK = equipos.filter(e => (e.errors || 0) === 0 && (e.warnings || 0) === 0).length;
  const equiposWarning = equipos.filter(e => (e.errors || 0) === 0 && (e.warnings || 0) > 0).length;
  const equiposCriticos = equipos.filter(e => (e.errors || 0) > 0).length;
  const scorePromedio = equipos.length > 0
    ? Math.round(equipos.reduce((sum, e) => sum + e.compliance_score, 0) / totalEquipos * 10) / 10
    : 0;

  const metricas = {
    total_equipos: totalEquipos,
    equipos_ok: equiposOK,
    equipos_warning: equiposWarning,
    equipos_criticos: equiposCriticos,
    score_promedio: scorePromedio
  };

  // Analizar problemas comunes entre todos los equipos
  const problemasAgrupados = analizarProblemasGlobales(equipos);

  // Ordenar equipos por score (peor primero)
  const equiposOrdenados = [...equipos].sort((a, b) => a.compliance_score - b.compliance_score);

  // Calcular métricas de controles
  const metricasControles = calcularMetricasControles(equipos);

  const fechaFormateada = new Date(fecha).toLocaleDateString('es-ES', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  const colorScore = scorePromedio >= 90 ? '#28a745' : scorePromedio >= 80 ? '#ffc107' : '#dc3545';
  const hoy = new Date().toLocaleDateString('es-ES', { year: 'numeric', month: 'long', day: 'numeric' });

  const html = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Auditoría Hardening ISO 27001 - Reporte Global</title>
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background: #f4f6f8; }
    .container { max-width: 900px; margin: 0 auto; padding: 20px; }
    .header { background: #ffffff; color: #333333; border-bottom: 5px solid #667eea; padding: 30px; border-radius: 10px 10px 0 0; text-align: center; }
    .header h1 { margin: 0; font-size: 26px; color: #333; }
    .header p { margin: 5px 0 0; color: #666; }
    .section { background: #f8f9fa; padding: 20px; margin: 20px 0; border-left: 4px solid #667eea; border-radius: 5px; }
    .section h2 { margin-top: 0; color: #444; font-size: 18px; }
    .metrics-row { display: flex; justify-content: space-around; flex-wrap: wrap; margin: 20px 0; }
    .metric { text-align: center; background: white; padding: 20px; border-radius: 8px; min-width: 150px; margin: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); }
    .metric-value { font-size: 36px; font-weight: bold; display: block; }
    .metric-label { font-size: 12px; color: #6c757d; text-transform: uppercase; }
    .problema { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); }
    .prioridad-alta { border-left: 5px solid #dc3545; }
    .prioridad-media { border-left: 5px solid #ffc107; }
    .prioridad-baja { border-left: 5px solid #17a2b8; }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; }
    th { background: #667eea; color: white; padding: 12px; text-align: left; font-size: 13px; }
    td { padding: 10px; border-bottom: 1px solid #dee2e6; font-size: 13px; }
    tr:hover td { background: #f8f9fa; }
    .control-card { background: white; padding: 15px; border-radius: 5px; margin-bottom: 10px; }
    .controles-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .badge-ok { background: #d4edda; color: #155724; padding: 2px 8px; border-radius: 12px; font-size: 12px; }
    .badge-warning { background: #fff3cd; color: #856404; padding: 2px 8px; border-radius: 12px; font-size: 12px; }
    .badge-error { background: #f8d7da; color: #721c24; padding: 2px 8px; border-radius: 12px; font-size: 12px; }
    .link-box { background: #d1ecf1; padding: 20px; border-radius: 5px; border-left: 4px solid #17a2b8; margin: 20px 0; }
    .btn { display: inline-block; padding: 10px 20px; background: #667eea; color: white; text-decoration: none; border-radius: 5px; margin: 5px; font-size: 14px; }
    .footer { background: #343a40; color: white; padding: 20px; text-align: center; border-radius: 0 0 10px 10px; font-size: 12px; margin-top: 0; }
    pre { background: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 12px; }
    .equipos-list { font-size: 11px; color: #6c757d; margin-top: 5px; font-style: italic; }
    .score-critico { color: #dc3545; font-weight: bold; }
    .score-warning { color: #fd7e14; font-weight: bold; }
    .score-ok { color: #28a745; font-weight: bold; }
  </style>
</head>
<body>
<div class="container">

<!-- HEADER -->
<div class="header">
  <h1>🔒 Auditoría de Hardening ISO 27001 + ENS</h1>
  <p>Sisteplant - Departamento de Sistemas</p>
  <p>${fechaFormateada}</p>
</div>

<!-- SECCIÓN 1: RESUMEN EJECUTIVO -->
<div class="section">
  <h2>📊 Resumen Ejecutivo</h2>
  <p>${generarResumenGlobal(equipos, scorePromedio, equiposCriticos)}</p>
  
  <div class="metrics-row">
    <div class="metric">
      <span class="metric-value" style="color: ${colorScore}">${scorePromedio}%</span>
      <span class="metric-label">Score Promedio</span>
    </div>
    <div class="metric">
      <span class="metric-value">${totalEquipos}</span>
      <span class="metric-label">Equipos Auditados</span>
    </div>
    <div class="metric">
      <span class="metric-value" style="color: #dc3545">${equiposCriticos}</span>
      <span class="metric-label">Críticos (errores)</span>
    </div>
    <div class="metric">
      <span class="metric-value" style="color: #ffc107">${equiposWarning}</span>
      <span class="metric-label">Con Warnings</span>
    </div>
    <div class="metric">
      <span class="metric-value" style="color: #28a745">${equiposOK}</span>
      <span class="metric-label">Sin Alertas</span>
    </div>
  </div>
</div>

<!-- SECCIÓN 2: TOP PROBLEMAS PRIORITARIOS -->
<div class="section">
  <h2>🎯 Top Problemas Prioritarios</h2>
  <p><strong>Acción requerida inmediata:</strong></p>
  ${problemasAgrupados.map((p, i) => `
  <div class="problema prioridad-${p.prioridad.toLowerCase()}">
    <h3>${i + 1}. ${p.nombre} - Prioridad ${p.urgencia}</h3>
    <p><strong>📊 Alcance:</strong> ${p.equiposAfectados.length} equipo(s) afectado(s) (${Math.round(p.equiposAfectados.length / totalEquipos * 100)}% del total)</p>
    ${p.equiposAfectados.length <= 10 ? `<p><strong>Equipos:</strong> ${p.equiposAfectados.join(', ')}</p>` : `<div class="equipos-list">Equipos: ${p.equiposAfectados.slice(0, 5).join(', ')}${p.equiposAfectados.length > 5 ? ` y ${p.equiposAfectados.length - 5} más` : ''}</div>`}
    <p><strong>🔍 Control ISO 27001 + ENS:</strong> <code>${p.control}</code> - ${p.nombreControl}</p>
    <p><strong>✅ Solución:</strong> ${p.solucion}</p>
    ${p.comando ? `<pre>${p.comando}</pre>` : ''}
    <p><strong>⏱️ Tiempo estimado:</strong> ${p.tiempo}</p>
    <p><strong>📝 Documentación ISO + ENS requerida:</strong></p>
    <ul><li>${p.documentacion}</li></ul>
  </div>`).join('')}
</div>

<!-- SECCIÓN 3: MÉTRICAS DE CUMPLIMIENTO POR CONTROL -->
<div class="section">
  <h2>📈 Métricas de Cumplimiento por Control</h2>
  <p style="font-size: 13px; color: #6c757d; margin-bottom: 20px;">Estado de cumplimiento por cada control crítico (ISO 27001 + ENS):</p>
  <div class="controles-grid">
    ${metricasControles.map(mc => {
    const equiposCumplen = totalEquipos - mc.equiposFallo;
    const pct = totalEquipos > 0 ? Math.round((equiposCumplen / totalEquipos) * 100) : 0;
    const color = pct < 50 ? '#dc3545' : pct < 80 ? '#ffc107' : '#28a745';
    const borderColor = pct < 50 ? '#dc3545' : pct < 80 ? '#ffc107' : '#28a745';
    return `<div class="control-card" style="border-left: 3px solid ${borderColor};">
        <h4 style="margin:0 0 5px">${mc.icono} ${mc.nombre}</h4>
        <div style="font-size: 24px; font-weight: bold; color: ${color}">${pct}%</div>
        <p style="font-size:13px; margin:2px 0">${pct}% de los equipos cumplen con ${mc.control}</p>
        <p style="font-size:11px; margin:2px 0; color: #6c757d;">${equiposCumplen} cumplen / ${mc.equiposFallo} no cumplen</p>
        ${mc.equiposFallo > 0 && mc.equiposFallo <= 10 ? `<div class="equipos-list" style="color:#dc3545;">Atención en: ${mc.hostnames.join(', ')}</div>` : mc.equiposFallo > 10 ? `<div class="equipos-list" style="color:#dc3545;">Atención en: ${mc.hostnames.slice(0, 5).join(', ')} y ${mc.equiposFallo - 5} más</div>` : ''}
      </div>`;
  }).join('')}
  </div>
</div>

<!-- SECCIÓN 4: EQUIPOS QUE REQUIEREN ATENCIÓN -->
<div class="section">
  <h2>🚨 Equipos que Requieren Atención</h2>
  <p style="font-size: 13px; color: #6c757d;">Ordenados por score (peor primero):</p>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Hostname</th>
        <th>Score</th>
        <th>Errores</th>
        <th>Warnings</th>
        <th>Principales Problemas</th>
      </tr>
    </thead>
    <tbody>
      ${equiposOrdenados.filter(e => (e.errors || 0) > 0 || (e.warnings || 0) > 0 || e.compliance_score < 90).slice(0, 20).map((e, i) => {
    const scoreClass = e.compliance_score < 70 ? 'score-critico' : e.compliance_score < 85 ? 'score-warning' : 'score-ok';
    const problemas = extraerResumenProblemas(e);
    return `<tr>
          <td>${i + 1}</td>
          <td><strong>${e.hostname}</strong></td>
          <td class="${scoreClass}">${e.compliance_score}%</td>
          <td>${e.errors || 0}</td>
          <td>${e.warnings || 0}</td>
          <td style="font-size:12px">${problemas}</td>
        </tr>`;
  }).join('')}
      ${equiposOrdenados.filter(e => (e.errors || 0) > 0 || (e.warnings || 0) > 0 || e.compliance_score < 90).length > 20 ?
      `<tr style="background:#f8f9fa"><td colspan="6" style="text-align:center;font-style:italic;padding:15px;">
          ${equiposOrdenados.filter(e => (e.errors || 0) > 0 || (e.warnings || 0) > 0 || e.compliance_score < 90).length - 20} equipos adicionales. Ver Excel Dashboard para detalles.
        </td></tr>` : ''}
    </tbody>
  </table>
</div>

<!-- SECCIÓN 5: GESTIÓN DE EVIDENCIA ISO 27001 -->
<div class="section">
  <h2>📁 Gestión de Historial y Evidencia ISO 27001 + ENS</h2>
  <h3>📍 Ubicación de Evidencias</h3>
  <ul>
    <li><strong>Dashboard Excel:</strong> OneDrive &gt; Hardening_ISO27001 &gt; Dashboard_Hardening_ISO27001_Sisteplant.xlsx</li>
    <li><strong>Archivos JSON:</strong> OneDrive &gt; Hardening_ISO27001 &gt; PROCESADOS (retención 12 meses)</li>
    <li><strong>Logs Action1:</strong> Consola Action1 &gt; Executions</li>
  </ul>
  <h3>📝 Documentación Obligatoria por Remediación</h3>
  <ol>
    <li><strong>Registro de Control de Cambios:</strong> Fecha, responsable, descripción, equipos, control ISO/ENS, resultado</li>
    <li><strong>Evidencia de Implementación:</strong> Screenshots, logs de ejecución</li>
    <li><strong>Verificación Post-Implementación:</strong> Nueva auditoría parcial en 7 días</li>
    <li><strong>Actualización de Documentos ISO + ENS:</strong> Inventario de Activos, Política de Seguridad, Matriz de Riesgos</li>
  </ol>
</div>

<!-- SECCIÓN 6: ACCESO A DOCUMENTACIÓN -->
<div class="link-box">
  <h2>📊 Acceso a Documentación Completa</h2>
  <p><strong>Para análisis detallado y gestión de hallazgos:</strong></p>
  <a href="https://sisteplant-my.sharepoint.com/:x:/r/personal/sistemas_sisteplant_com/_layouts/15/Doc.aspx?sourcedoc=%7B68586505-9415-414A-B955-13FA29BD72CF%7D&file=Dashboard_Hardening_ISO27001_Sisteplant.xlsx&action=default&mobileredirect=true" class="btn" target="_blank">
    📊 Abrir Dashboard Excel
  </a>
  <p style="margin-top: 15px;"><strong>Hojas clave en el Excel:</strong></p>
  <ul>
    <li><strong>Dashboard Actual:</strong> Vista gerencial con última auditoría por equipo</li>
    <li><strong>Hallazgos:</strong> Lista completa para seguimiento (asignar responsable, estado)</li>
    <li><strong>Análisis IA:</strong> Detalle completo del análisis de cada equipo crítico</li>
  </ul>
</div>

<!-- SECCIÓN 7: PRÓXIMOS PASOS (30 días) -->
<div class="section">
  <h2>🚀 Próximos Pasos Inmediatos (30 días)</h2>
  <table>
    <thead><tr><th>Día</th><th>Acción</th><th>Responsable</th></tr></thead>
    <tbody>
      <tr><td><strong>0-3</strong></td><td>Revisar problemas prioritarios y asignar responsables</td><td>Jefe de Sistemas</td></tr>
      <tr><td><strong>3-7</strong></td><td>Aplicar remediaciones prioridad INMEDIATA vía Action1/GPO</td><td>Equipo IT</td></tr>
      <tr><td><strong>7</strong></td><td>Re-auditar equipos críticos para verificar mejora</td><td>Action1 (automatizado)</td></tr>
      <tr><td><strong>7-14</strong></td><td>Documentar cambios en Registro de Control de Cambios</td><td>Responsable ISO 27001 + ENS</td></tr>
      <tr><td><strong>14-30</strong></td><td>Aplicar remediaciones prioridad MEDIA</td><td>Equipo IT</td></tr>
      <tr><td><strong>30</strong></td><td>Revisar métricas de progreso en Dashboard Excel</td><td>Jefe de Sistemas</td></tr>
    </tbody>
  </table>
</div>

<!-- FOOTER -->
<div class="footer">
  <p><strong>Sistema de Auditoría Automatizada - Sisteplant IT</strong></p>
  <p>Script PowerShell v5.4.9 | 27 controles de seguridad | ISO 27001:2022 + ENS</p>
  <p>Desplegado vía Action1 RMM | Análisis: Hardening Analyzer v3.1</p>
  <hr style="border: 0; border-top: 1px solid #495057; margin: 15px 0;">
  <p>Departamento de Sistemas - Sisteplant | sistemas@sisteplant.com</p>
  <p style="font-size: 10px; color: #adb5bd; margin-top: 10px;">Generado automáticamente el ${hoy}</p>
</div>

</div>
</body>
</html>`;

  return { html, metricas };
}

// ============================================================
// FUNCIONES AUXILIARES
// ============================================================

function extraerHallazgos(data: ComplianceData) {
  const findings: any[] = [];

  if (!data.checks) return findings;

  Object.entries(data.checks).forEach(([seccion, checks]) => {
    if (!checks || typeof checks !== 'object') return;
    Object.entries(checks).forEach(([checkName, checkData]) => {
      if (checkData && (checkData.estado === 'WARNING' || checkData.estado === 'ERROR')) {
        findings.push({
          seccion,
          check_name: checkName,
          estado: checkData.estado,
          criticidad: checkData.criticidad || 'MEDIA',
          detalle: checkData.detalle || 'Sin detalles'
        });
      }
    });
  });

  return findings;
}

function generarResumenEjecutivo(data: ComplianceData, findings: any[]): string {
  const hostname = data.hostname;
  const score = data.compliance_score;
  const errores = data.errors || 0;
  const warnings = data.warnings || 0;
  const criticos = findings.filter(f => f.criticidad === 'CRITICA' || f.criticidad === 'ALTA');

  // Casos especiales: SO sin soporte
  const soSinSoporte = data.sistema_operativo?.soporte_activo === false;
  const lapsFaltante = data.laps_detallado?.debe_tener_laps !== false &&
    !data.laps_detallado?.funcional && !data.laps_detallado?.gpo_aplicada;
  const bitlockerProblema = !data.bitlocker_detallado?.no_aplica &&
    (data.bitlocker_detallado?.encriptacion_porcentaje || 0) < 100;

  const problemasGraves: string[] = [];
  if (soSinSoporte) problemasGraves.push('Windows sin soporte activo de Microsoft');
  if (lapsFaltante && data.laps_detallado) problemasGraves.push('LAPS no instalado o no funcional');
  if (bitlockerProblema && data.bitlocker_detallado) problemasGraves.push(`BitLocker al ${data.bitlocker_detallado.encriptacion_porcentaje}%`);

  if (errores === 0 && warnings === 0) {
    return `El equipo ${hostname} cumple satisfactoriamente con todos los controles de hardening (${score}%). Score por encima del objetivo de 90%. Se recomienda mantener la configuración actual y continuar con auditorías periódicas.`;
  }

  let resumen = `El equipo ${hostname} presenta score de cumplimiento del ${score}% (objetivo: 90%)`;
  if (errores > 0) resumen += `, con ${errores} error(es) crítico(s) que requieren atención inmediata`;
  if (warnings > 0) resumen += ` y ${warnings} advertencia(s)`;
  resumen += '.';

  if (problemasGraves.length > 0) {
    resumen += ` Problemas principales: ${problemasGraves.join('; ')}.`;
  } else if (criticos.length > 0) {
    resumen += ` Principales hallazgos: ${criticos.slice(0, 2).map(f => f.check_name).join(', ')}.`;
  }

  resumen += errores > 0 ? ' Se requiere plan de remediación urgente.' : ' Se recomienda plan de mejora.';

  return resumen;
}


function generarMapeoISO(findings: any[], controlesAfectados: any[], impactoCertificacion: string, score: number, errores: number) {
  const controlesDetallados = controlesAfectados.map(control => {
    const hallazgosRelacionados = findings.filter(f => {
      const mapaControl = MAPEO_VERIFICACIONES_ISO[f.check_name] || [];
      return mapaControl.includes(control.id);
    });

    let estado: 'NO_CONFORME' | 'PARCIAL' | 'CONFORME' = 'CONFORME';
    if (hallazgosRelacionados.some(h => h.estado === 'ERROR')) {
      estado = 'NO_CONFORME';
    } else if (hallazgosRelacionados.some(h => h.estado === 'WARNING')) {
      estado = 'PARCIAL';
    }

    return {
      codigo: control.id,
      nombre: control.nombre,
      estado: estado,
      hallazgo_relacionado: hallazgosRelacionados.slice(0, 2).map(h => h.check_name).join(', ') || 'N/A',
      control_ens: obtenerControlENS(control.id)
    };
  });

  // Calcular impacto
  let impactoFinal = 'BAJO';
  if (errores > 0 || controlesDetallados.some(c => c.estado === 'NO_CONFORME')) {
    impactoFinal = 'CRÍTICO';
  } else if (score < 80 || controlesDetallados.some(c => c.estado === 'PARCIAL')) {
    impactoFinal = score < 70 ? 'ALTO' : 'MEDIO';
  }

  const requisitosPendientes = controlesDetallados
    .filter(c => c.estado !== 'CONFORME')
    .map(c => `${c.codigo}: Resolver ${c.estado === 'NO_CONFORME' ? 'no conformidad' : 'conformidad parcial'}`)
    .join('; ') || 'N/A';

  return {
    controles_afectados: controlesDetallados,
    impacto_certificacion: impactoFinal,
    requisitos_pendientes: requisitosPendientes
  };
}

function generarRiesgos(data: ComplianceData, findings: any[], criticos: any[]) {
  const riesgos: any[] = [];

  // Riesgo 1: SO sin soporte
  if (data.sistema_operativo?.soporte_activo === false) {
    riesgos.push({
      descripcion: `Windows ${data.sistema_operativo.nombre || ''} build ${data.sistema_operativo.build || ''}: Sistema operativo sin soporte oficial de Microsoft. Vulnerabilidades sin parches.`,
      criticidad: 'ALTA',
      impacto: 'Exposición a vulnerabilidades críticas sin corrección oficial. Incumplimiento normativo.',
      control_iso27001: 'A.12.6',
      control_ens: 'op.pl.2',
      evidencia: `sistema_operativo.soporte_activo = false`
    });
  }

  // Riesgo 2: LAPS no instalado
  if (data.laps_detallado?.debe_tener_laps !== false && (!data.laps_detallado?.instalado || !data.laps_detallado?.funcional)) {
    riesgos.push({
      descripcion: `LAPS (Local Admin Password Solution) no ${data.laps_detallado?.instalado ? 'funcional' : 'instalado'}${data.laps_detallado?.motivo_fallo ? ': ' + data.laps_detallado.motivo_fallo : ''}. Contraseña de administrador local sin rotación.`,
      criticidad: 'ALTA',
      impacto: 'Credenciales de administrador local estáticas. Riesgo de movimiento lateral en la red.',
      control_iso27001: 'A.9.2',
      control_ens: 'op.acc.5',
      evidencia: `laps_detallado.funcional = ${data.laps_detallado?.funcional}`
    });
  }

  // Riesgo 3: BitLocker incompleto
  if (!data.bitlocker_detallado?.no_aplica && ((data.bitlocker_detallado?.encriptacion_porcentaje || 0) < 100 || data.bitlocker_detallado?.secure_boot === false)) {
    const desc = [];
    if ((data.bitlocker_detallado?.encriptacion_porcentaje || 0) < 100) {
      desc.push(`cifrado al ${data.bitlocker_detallado?.encriptacion_porcentaje || 0}%`);
    }
    if (data.bitlocker_detallado?.secure_boot === false) desc.push('Secure Boot desactivado');
    if (!data.bitlocker_detallado?.gpo_aplicada) desc.push('GPO BitLocker no aplicada');

    riesgos.push({
      descripcion: `BitLocker: ${desc.join(', ')}. ${data.bitlocker_detallado?.motivo_fallo || ''}`,
      criticidad: (data.bitlocker_detallado?.encriptacion_porcentaje || 0) < 50 ? 'ALTA' : 'MEDIA',
      impacto: 'Datos sin cifrado completo. Riesgo de exposición de información ante pérdida o robo del dispositivo.',
      control_iso27001: 'A.8.3',
      control_ens: 'op.exp.10',
      evidencia: `bitlocker_detallado.encriptacion_porcentaje = ${data.bitlocker_detallado?.encriptacion_porcentaje || 0}`
    });
  }

  // Riesgos adicionales basados en hallazgos críticos
  for (const finding of criticos) {
    if (riesgos.length >= 3) break;
    const controlesISO = MAPEO_VERIFICACIONES_ISO[finding.check_name] || ['A.8.9'];
    riesgos.push({
      descripcion: `${finding.check_name}: ${finding.detalle}`,
      criticidad: finding.criticidad === 'CRITICA' ? 'ALTA' : finding.criticidad === 'ALTA' ? 'ALTA' : 'MEDIA',
      impacto: `${finding.seccion}: incumplimiento de control de seguridad`,
      control_iso27001: controlesISO[0] || 'A.8.9',
      control_ens: obtenerControlENS(controlesISO[0]),
      evidencia: `checks.${finding.seccion}.${finding.check_name}.estado = ${finding.estado}`
    });
  }

  return riesgos.slice(0, 3);
}

function generarAcciones(data: ComplianceData, findings: any[], criticos: any[], medios: any[]) {
  const acciones: any[] = [];

  // Acción 1: SO sin soporte → actualizar Windows
  if (data.sistema_operativo?.soporte_activo === false) {
    acciones.push({
      accion: `Actualizar sistema operativo a Windows 11 23H2 (build 22631) o superior con soporte activo. Actual: ${data.sistema_operativo.nombre || ''} build ${data.sistema_operativo.build || ''}`,
      prioridad: 1,
      tipo: 'técnica',
      herramienta: 'Action1 / Windows Update / SCCM',
      comando: `# Verificar versión actual\nGet-ComputerInfo | Select OsName, OsVersion, WindowsBuildLabEx`,
      tiempo_estimado: '2-4 horas por equipo',
      responsable_sugerido: 'Admin TI',
      documentacion_iso: 'Inventario de Activos (actualizar SO), Control de Cambios, Política de Gestión de Vulnerabilidades'
    });
  }

  // Acción 2: LAPS
  if (data.laps_detallado?.debe_tener_laps !== false && (!data.laps_detallado?.instalado || !data.laps_detallado?.funcional)) {
    acciones.push({
      accion: `Instalar y configurar LAPS en OU: ${data.laps_detallado?.ou_equipo || 'Desconocida'}. Usuario esperado: ${data.laps_detallado?.usuario_esperado || 'robin'}`,
      prioridad: 2,
      tipo: 'técnica',
      herramienta: 'Action1 / GPO / PowerShell',
      comando: `# Instalar LAPS via Action1 o GPO\nInstall-Package -Name "Microsoft LAPS"\n# Verificar instalación\nGet-Command *laps* -ErrorAction SilentlyContinue`,
      tiempo_estimado: '30-60 minutos',
      responsable_sugerido: 'Admin TI',
      documentacion_iso: 'Política de Gestión de Contraseñas, Control de Cambios (A.9.2 / op.acc.5)'
    });
  }

  // Acción 3: BitLocker/SecureBoot
  if (data.bitlocker_detallado?.secure_boot === false) {
    acciones.push({
      accion: `Habilitar Secure Boot en BIOS/UEFI del equipo ${data.hostname}`,
      prioridad: acciones.length + 1,
      tipo: 'técnica',
      herramienta: 'BIOS/UEFI Manual',
      comando: `# Verificar estado Secure Boot\nConfirm-SecureBootUEFI\n# Entrar a BIOS: F10/DEL/F2 al arrancar`,
      tiempo_estimado: '15-30 minutos',
      responsable_sugerido: 'Técnico IT (presencial)',
      documentacion_iso: 'Control de Cambios, Inventario de Activos (A.8.3 / op.exp.10)'
    });
  }

  // Acciones adicionales de hallazgos críticos
  for (const finding of [...criticos, ...medios]) {
    if (acciones.length >= 5) break;
    const accion = generarAccionParaHallazgo(finding);
    if (accion) acciones.push({ ...accion, prioridad: acciones.length + 1 });
  }

  return acciones.slice(0, 5);
}

function generarAccionParaHallazgo(finding: any) {
  const mapaAcciones: Record<string, any> = {
    'wazuh_agent': {
      accion: 'Instalar y activar agente Wazuh SIEM para monitoreo de seguridad',
      herramienta: 'Action1 / Wazuh Manager',
      comando: `# Verificar servicio Wazuh\nGet-Service WazuhSvc -ErrorAction SilentlyContinue`,
      tiempo_estimado: '30-45 minutos',
      documentacion_iso: 'Política de Monitoreo (A.12.4 / mp.si.2)'
    },
    'firewall': {
      accion: 'Activar y configurar Windows Firewall correctamente',
      herramienta: 'GPO / PowerShell',
      comando: `Set-NetFirewallProfile -All -Enabled True`,
      tiempo_estimado: '15 minutos',
      documentacion_iso: 'Política de Seguridad de Red (A.13.1 / mp.si.2)'
    },
    'antivirus_activo': {
      accion: 'Activar y actualizar protección antivirus/antimalware',
      herramienta: 'Action1 / Defender',
      comando: `Update-MpSignature; Start-MpScan -ScanType QuickScan`,
      tiempo_estimado: '15-30 minutos',
      documentacion_iso: 'Política de Control de Malware (A.12.5 / mp.si.1)'
    },
    'windows_update': {
      accion: 'Aplicar actualizaciones pendientes de Windows',
      herramienta: 'Action1 / WSUS / Windows Update',
      comando: `# Verificar actualizaciones pendientes\nGet-WindowsUpdate`,
      tiempo_estimado: '1-3 horas',
      documentacion_iso: 'Gestión de Vulnerabilidades (A.12.6 / mp.eq.3)'
    },
    'smbv1': {
      accion: 'Deshabilitar protocolo SMBv1 (vulnerable a ransomware)',
      herramienta: 'GPO / PowerShell',
      comando: `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force`,
      tiempo_estimado: '10 minutos (requiere reinicio)',
      documentacion_iso: 'Política de Transferencia de Información (A.13.2)'
    }
  };

  const plantilla = mapaAcciones[finding.check_name];
  if (plantilla) {
    return {
      accion: plantilla.accion,
      tipo: 'técnica',
      herramienta: plantilla.herramienta,
      comando: plantilla.comando,
      tiempo_estimado: plantilla.tiempo_estimado,
      responsable_sugerido: 'Admin TI',
      documentacion_iso: plantilla.documentacion_iso
    };
  }

  // Acción genérica
  return {
    accion: `Resolver: ${finding.check_name} - ${finding.detalle}`,
    tipo: 'técnica',
    herramienta: 'Action1 / Manual',
    tiempo_estimado: '30-60 minutos',
    responsable_sugerido: 'Admin TI',
    documentacion_iso: 'Control de Cambios, actualizar Registro de Hallazgos'
  };
}

function generarComentariosSeguimiento(data: ComplianceData, findings: any[]): string {
  const comentarios: string[] = [];

  if (data.errors && data.errors > 0) {
    comentarios.push(`${data.errors} error(es) crítico(s) pendientes de resolución`);
  }
  if (data.sistema_operativo?.soporte_activo === false) {
    comentarios.push('SO sin soporte: planificar actualización urgente');
  }
  if (data.compliance_score < 80) {
    comentarios.push('Score por debajo del mínimo aceptable (80%)');
  }

  return comentarios.join('. ') || 'Monitoreo continuo recomendado';
}

function obtenerControlENS(isoControl: string): string {
  const mapaENS: Record<string, string> = {
    'A.5.1': 'org.1',
    'A.8.3': 'op.exp.10',
    'A.8.9': 'op.exp.3',
    'A.8.23': 'op.exp.8',
    'A.9.2': 'op.acc.5',
    'A.9.4': 'op.acc.6',
    'A.12.4': 'mp.si.2',
    'A.12.5': 'mp.si.1',
    'A.12.6': 'mp.eq.3',
    'A.13.1': 'mp.si.2',
    'A.13.2': 'op.exp.7'
  };
  return mapaENS[isoControl] || '';
}

// ============================================================
// FUNCIONES PARA ANÁLISIS GLOBAL
// ============================================================

function generarResumenGlobal(equipos: ComplianceData[], scorePromedio: number, criticos: number): string {
  const total = equipos.length;
  const porcentajeCriticos = Math.round(criticos / total * 100);

  if (criticos === 0 && scorePromedio >= 90) {
    return `Excelente auditoría: ${total} equipo(s) auditado(s) con score promedio del ${scorePromedio}%. Todos los equipos cumplen el objetivo de 90%. Se recomienda mantener los controles actuales y continuar con auditorías periódicas.`;
  }

  if (criticos > 0) {
    return `Auditoría completada: ${total} equipo(s) analizados con score promedio del ${scorePromedio}%. Se detectó(aron) ${criticos} equipo(s) con errores críticos (${porcentajeCriticos}% del total) que requieren acción inmediata. Revisar plan de remediación en la sección siguiente.`;
  }

  return `Auditoría completada: ${total} equipo(s) analizados con score promedio del ${scorePromedio}%. Score por debajo del objetivo del 90%. Se recomienda plan de mejora para alcanzar el estándar requerido por ISO 27001.`;
}

function analizarProblemasGlobales(equipos: ComplianceData[]) {
  const problemas: any[] = [];

  // Problema: SO sin soporte
  const soSinSoporte = equipos.filter(e => e.sistema_operativo?.soporte_activo === false);
  if (soSinSoporte.length > 0) {
    problemas.push({
      nombre: 'Windows sin Soporte Oficial',
      prioridad: 'ALTA',
      urgencia: 'INMEDIATA',
      control: 'A.12.6 / op.pl.2',
      nombreControl: 'Gestión de Vulnerabilidad Técnica / Sistema Operativo Soportado',
      equiposAfectados: soSinSoporte.map(e => e.hostname),
      solucion: 'Actualizar a Windows 11 23H2 (build 22631) o Windows 10 22H2 con soporte activo',
      comando: '# Verificar versión actual\nGet-ComputerInfo | Select OsName, OsVersion',
      tiempo: '2-4 horas por equipo (planificar ventana de mantenimiento)',
      documentacion: 'Inventario de Activos (actualizar SO), Control de Cambios, Política de Gestión de Vulnerabilidades'
    });
  }

  // Problema: LAPS
  const sinLAPS = equipos.filter(e =>
    e.laps_detallado?.debe_tener_laps !== false &&
    !e.laps_detallado?.funcional && !e.laps_detallado?.gpo_aplicada
  );
  if (sinLAPS.length > 0) {
    problemas.push({
      nombre: 'LAPS no Instalado o no Funcional',
      prioridad: 'ALTA',
      urgencia: '7 DÍAS',
      control: 'A.9.2 / op.acc.5',
      nombreControl: 'Gestión de Acceso de Usuarios / Mecanismo de Autenticación',
      equiposAfectados: sinLAPS.map(e => e.hostname),
      solucion: 'Instalar Microsoft LAPS y configurar GPO de rotación de contraseñas de administrador local',
      comando: 'Install-Package -Name "Microsoft LAPS"\nGet-LapsADPassword -Identity $env:COMPUTERNAME',
      tiempo: '30-60 minutos por OU',
      documentacion: 'Política de Gestión de Contraseñas, Control de Cambios (A.9.2 / op.acc.5)'
    });
  }

  // Problema: BitLocker/Secure Boot
  const sinSecureBoot = equipos.filter(e => e.bitlocker_detallado?.secure_boot === false);
  if (sinSecureBoot.length > 0) {
    problemas.push({
      nombre: 'Secure Boot Desactivado',
      prioridad: 'MEDIA',
      urgencia: '7 DÍAS',
      control: 'A.8.3 / op.exp.10',
      nombreControl: 'Manipulación de Soportes / Cifrado de Almacenamiento',
      equiposAfectados: sinSecureBoot.map(e => e.hostname),
      solucion: 'Habilitar Secure Boot en BIOS/UEFI de cada equipo afectado',
      comando: '# Verificar estado\nConfirm-SecureBootUEFI\n# Habilitar: F10/DEL/F2 al arrancar → BIOS → Security → Secure Boot',
      tiempo: '15-30 minutos por equipo (presencial)',
      documentacion: 'Control de Cambios, Inventario de Activos (A.8.3 / op.exp.10)'
    });
  }

  // Problema: Errores de firewall/antivirus/wazuh (agregados de hallazgos)
  const hallazgosAgrupados: Record<string, ComplianceData[]> = {};
  equipos.forEach(equipo => {
    if (!equipo.checks) return;
    Object.values(equipo.checks).forEach((checksObj: any) => {
      if (!checksObj) return;
      Object.entries(checksObj).forEach(([checkName, checkData]: any) => {
        if (checkData?.estado === 'ERROR') {
          if (!hallazgosAgrupados[checkName]) hallazgosAgrupados[checkName] = [];
          if (!hallazgosAgrupados[checkName].includes(equipo)) {
            hallazgosAgrupados[checkName].push(equipo);
          }
        }
      });
    });
  });

  const infoHallazgos: Record<string, any> = {
    'wazuh_agent': { nombre: 'Agente Wazuh no Funcional', control: 'A.12.4 / mp.si.2', prioridad: 'ALTA', urgencia: '48 HORAS', solucion: 'Reinstalar agente Wazuh y verificar conexión al servidor SIEM', tiempo: '30 minutos', documentacion: 'Política de Monitoreo (A.12.4 / mp.si.2)' },
    'firewall': { nombre: 'Firewall Desactivado o Mal Configurado', control: 'A.13.1 / mp.si.2', prioridad: 'ALTA', urgencia: 'INMEDIATA', solucion: 'Activar Windows Firewall en todos los perfiles (Domain/Private/Public)', tiempo: '15 minutos', documentacion: 'Política de Seguridad de Red (A.13.1)' },
    'antivirus_activo': { nombre: 'Antivirus Desactivado o sin Actualizar', control: 'A.12.5 / mp.si.1', prioridad: 'ALTA', urgencia: 'INMEDIATA', solucion: 'Activar Windows Defender o solución antimalware corporativa', tiempo: '15-30 minutos', documentacion: 'Política de Control de Malware (A.12.5 / mp.si.1)' }
  };

  Object.entries(hallazgosAgrupados).forEach(([checkName, afectados]) => {
    if (problemas.length >= 5) return;
    const info = infoHallazgos[checkName];
    if (info && afectados.length > 0) {
      problemas.push({
        ...info,
        nombreControl: info.control,
        equiposAfectados: afectados.map((e: ComplianceData) => e.hostname),
        comando: null
      });
    }
  });

  return problemas.slice(0, 5);
}

function calcularMetricasControles(equipos: ComplianceData[]) {
  const total = equipos.length;
  if (total === 0) return [];

  const metricas = [
    {
      icono: '🪟', nombre: 'Windows Soportado', control: 'A.12.6 / op.pl.2',
      equiposFallo: equipos.filter(e => e.sistema_operativo?.soporte_activo === false).length,
      hostnames: equipos.filter(e => e.sistema_operativo?.soporte_activo === false).map(e => e.hostname)
    },
    {
      icono: '🔐', nombre: 'LAPS', control: 'A.9.2 / op.acc.5',
      equiposFallo: equipos.filter(e => e.laps_detallado?.debe_tener_laps !== false && !e.laps_detallado?.funcional && !e.laps_detallado?.gpo_aplicada).length,
      hostnames: equipos.filter(e => e.laps_detallado?.debe_tener_laps !== false && !e.laps_detallado?.funcional && !e.laps_detallado?.gpo_aplicada).map(e => e.hostname)
    },
    {
      icono: '💾', nombre: 'BitLocker Completo', control: 'A.8.3 / op.exp.10',
      equiposFallo: equipos.filter(e => !e.bitlocker_detallado?.no_aplica && ((e.bitlocker_detallado?.encriptacion_porcentaje || 0) < 100 || e.bitlocker_detallado?.secure_boot === false)).length,
      hostnames: equipos.filter(e => !e.bitlocker_detallado?.no_aplica && ((e.bitlocker_detallado?.encriptacion_porcentaje || 0) < 100 || e.bitlocker_detallado?.secure_boot === false)).map(e => e.hostname)
    },
    {
      icono: '🛡️', nombre: 'Firewall Activo', control: 'A.13.1 / mp.si.2',
      equiposFallo: equipos.filter(e => tieneErrorCheck(e, 'firewall')).length,
      hostnames: equipos.filter(e => tieneErrorCheck(e, 'firewall')).map(e => e.hostname)
    },
    {
      icono: '🦠', nombre: 'Antivirus', control: 'A.12.5 / mp.si.1',
      equiposFallo: equipos.filter(e => tieneErrorCheck(e, 'antivirus_activo')).length,
      hostnames: equipos.filter(e => tieneErrorCheck(e, 'antivirus_activo')).map(e => e.hostname)
    },
    {
      icono: '👁️', nombre: 'Wazuh SIEM', control: 'A.12.4 / mp.si.2',
      equiposFallo: equipos.filter(e => tieneErrorCheck(e, 'wazuh_agent')).length,
      hostnames: equipos.filter(e => tieneErrorCheck(e, 'wazuh_agent')).map(e => e.hostname)
    },
    {
      icono: '🔄', nombre: 'Windows Update', control: 'A.12.6 / mp.eq.3',
      equiposFallo: equipos.filter(e => tieneErrorCheck(e, 'windows_update')).length,
      hostnames: equipos.filter(e => tieneErrorCheck(e, 'windows_update')).map(e => e.hostname)
    },
    {
      icono: '🔑', nombre: 'SMBv1 Deshabilitado', control: 'A.13.2',
      equiposFallo: equipos.filter(e => tieneErrorCheck(e, 'smbv1')).length,
      hostnames: equipos.filter(e => tieneErrorCheck(e, 'smbv1')).map(e => e.hostname)
    }
  ];

  return metricas;
}

function tieneErrorCheck(equipo: ComplianceData, checkName: string): boolean {
  if (!equipo.checks) return false;
  for (const checksObj of Object.values(equipo.checks)) {
    if (!checksObj) continue;
    for (const [name, data] of Object.entries(checksObj as any)) {
      if (name === checkName && (data as any).estado === 'ERROR') return true;
    }
  }
  return false;
}

function extraerResumenProblemas(equipo: ComplianceData): string {
  const problemas: string[] = [];

  if (equipo.sistema_operativo?.soporte_activo === false) problemas.push('SO sin soporte');
  if (equipo.laps_detallado?.debe_tener_laps !== false && !equipo.laps_detallado?.funcional) problemas.push('LAPS faltante');
  if (!equipo.bitlocker_detallado?.no_aplica && (equipo.bitlocker_detallado?.encriptacion_porcentaje || 0) < 100) problemas.push('BitLocker incompleto');
  if (equipo.bitlocker_detallado?.secure_boot === false) problemas.push('Secure Boot OFF');

  if (problemas.length > 0) return problemas.slice(0, 3).join(', ');

  // Si no hay datos detallados, usar hallazgos del check
  const hallazgos: string[] = [];
  if (equipo.checks) {
    for (const checksObj of Object.values(equipo.checks)) {
      if (!checksObj) continue;
      for (const [name, data] of Object.entries(checksObj as any)) {
        if ((data as any).estado === 'ERROR') {
          hallazgos.push(name);
          if (hallazgos.length >= 3) break;
        }
      }
      if (hallazgos.length >= 3) break;
    }
  }

  return hallazgos.slice(0, 3).join(', ') || `Score ${equipo.compliance_score}%`;
}
