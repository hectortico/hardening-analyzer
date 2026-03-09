// types.ts - Tipos TypeScript para el proyecto

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
  domain: string;
  scan_date: string;
  usuario: string;
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
  duracion_seg: number;
  version_script: string;
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

export interface AnalysisResponse {
  hostname: string;
  fecha_analisis: string;
  score: number;
  resumen_ejecutivo: string;
  controles_iso_afectados: ControlISO27001[];
  riesgos_principales: string[];
  acciones_recomendadas: {
    accion: string;
    prioridad: 'ALTA' | 'MEDIA' | 'BAJA';
    plazo: string;
  }[];
  metricas_cumplimiento: {
    score_actual: number;
    score_objetivo: number;
    gap_critico: string;
  };
}

export interface GlobalAnalysisRequest {
  equipos: ComplianceData[];
  fecha_analisis: string;
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
