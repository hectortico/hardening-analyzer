// types.ts - Tipos TypeScript para el proyecto
// Versión 3.1 - Compatible con workflow N8N v5 FINAL

export interface ComplianceCheck {
  estado: 'OK' | 'WARNING' | 'ERROR';
  criticidad: 'BAJA' | 'MEDIA' | 'ALTA' | 'CRITICA';
  detalle: string;
  valor?: string | number;
  mensaje?: string;
  accion_aplicada?: string;
}

export interface ComplianceData {
  hostname: string;
  domain?: string;
  scan_date?: string;
  usuario?: string;
  compliance_score: number;
  total_checks: number;
  passed: number;
  warnings: number;
  errors: number;
  checks: {
    [seccion: string]: {
      [check: string]: ComplianceCheck;
    };
  };
  acciones_correctivas?: string[];
  duracion_seg?: number;
  version_script?: string;
  software_instalado?: { nombre: string; version: string }[];
  sistema_operativo?: {
    nombre?: string;
    version?: string;
    build?: string;
    soporte_activo?: boolean;
    fecha_fin_soporte?: string;
    dias_restantes?: number;
    critico?: boolean;
  };
  bitlocker_detallado?: {
    encriptacion_porcentaje?: number;
    tpm_version?: string;
    tpm_ready?: boolean;
    secure_boot?: boolean;
    gpo_aplicada?: boolean;
    motivo_fallo?: string;
  };
  laps_detallado?: {
    instalado?: boolean;
    funcional?: boolean;
    usuario_admin_actual?: string;
    usuario_esperado?: string;
    debe_tener_laps?: boolean;
    ou_equipo?: string;
    motivo_fallo?: string;
  };
}

export interface Finding {
  seccion: string;
  check_name: string;
  estado: 'WARNING' | 'ERROR';
  criticidad: 'BAJA' | 'MEDIA' | 'ALTA' | 'CRITICA';
  detalle: string;
}

export interface ControlISO27001 {
  id: string;
  nombre: string;
  descripcion: string;
  anexo: string;
}

// AnalysisResponse compatible con lo que espera el nodo "📊 Extraer Análisis IA" del workflow N8N
// El nodo espera la estructura de Gemini IA (análisis completo con 6 secciones)
export interface AnalysisResponse {
  hostname: string;
  fecha_analisis: string;
  compliance_score: number;
  score: number; // alias para compatibilidad

  // Resumen ejecutivo
  resumen_ejecutivo: string;

  // Mapeo ISO 27001 (estructura que espera el nodo)
  mapeo_iso27001: {
    controles_afectados: {
      codigo: string;
      nombre: string;
      estado: 'NO_CONFORME' | 'PARCIAL' | 'CONFORME';
      hallazgo_relacionado: string;
      control_ens?: string;
    }[];
    impacto_certificacion: string;
    requisitos_pendientes: string;
  };

  // Riesgos (3 principales)
  riesgos: {
    descripcion: string;
    criticidad: 'ALTA' | 'MEDIA' | 'BAJA';
    impacto: string;
    control_iso27001: string;
    control_ens?: string;
    evidencia?: string;
  }[];

  // Acciones recomendadas (5)
  acciones_recomendadas: {
    accion: string;
    prioridad: number | 'ALTA' | 'MEDIA' | 'BAJA';
    tipo?: string;
    herramienta: string;
    comando?: string;
    tiempo_estimado: string;
    responsable_sugerido?: string;
    documentacion_iso: string;
  }[];

  // Métricas
  metricas_cumplimiento: {
    score_actual: number;
    score_objetivo: number;
    gap_critico: string;
    tiempo_remediacion_estimado: string;
    controles_ok: number;
    controles_fallo: number;
  };

  // Seguimiento
  seguimiento: {
    proxima_revision: string;
    indicadores_clave: string[];
    tendencia: 'MEJORA' | 'ESTABLE' | 'DETERIORO' | 'DESCONOCIDA';
    comentarios: string;
  };
}

export interface GlobalAnalysisRequest {
  equipos: ComplianceData[];
  fecha_analisis?: string;
}

export interface GlobalAnalysisResponse {
  html: string;
  metricas: {
    total_equipos: number;
    equipos_ok: number;
    equipos_warning: number;
    equipos_criticos: number;
    score_promedio: number;
  };
}

// ============================================================
// SERVIDOR: ServerComplianceData extiende ComplianceData
// con campos especificos de Windows Server (v3.2)
// ============================================================
export interface ServerComplianceData extends ComplianceData {
  tipo_equipo?: 'SERVIDOR' | 'ENDPOINT';
  es_maquina_virtual?: boolean;
  tipo_virtualizacion?: string;

  zabbix_detallado?: {
    instalado?: boolean;
    funcional?: boolean;
    version?: string;
  };

  wazuh_detallado?: {
    instalado?: boolean;
    funcional?: boolean;
  };

  veeam_detallado?: {
    instalado?: boolean;
    funcional?: boolean;
    tipo?: string;
  };

  rdp_detallado?: {
    habilitado?: boolean;
    nla?: boolean;
    puerto?: number;
    cifrado?: number;
  };

  tls_detallado?: {
    tls10_habilitado?: boolean;
    tls11_habilitado?: boolean;
    tls12_habilitado?: boolean;
    ssl3_habilitado?: boolean;
  };
}

export interface ServerAnalysisRequest {
  servidor: ServerComplianceData;
  fecha_analisis?: string;
}
