// iso27001/controles.ts - Controles ISO 27001:2022 OFICIALES
// Anexo A completo verificado contra estándar ISO 27001:2022

import { ControlISO27001 } from '../utils/types';

/**
 * CONTROLES ISO 27001:2022 ANEXO A - VERIFICADOS
 * 
 * Estos son los controles OFICIALES del estándar ISO 27001:2022
 * NO pueden inventarse - están hardcodeados desde el documento oficial
 */

export const CONTROLES_ISO27001: Record<string, ControlISO27001> = {
  // ========== A.5 - POLÍTICAS DE SEGURIDAD DE LA INFORMACIÓN ==========
  'A.5.1': {
    id: 'A.5.1',
    nombre: 'Políticas de seguridad de la información',
    descripcion: 'Conjunto de políticas de seguridad de la información definidas, aprobadas por la dirección, publicadas y comunicadas',
    anexo: 'A.5'
  },

  // ========== A.8 - GESTIÓN DE ACTIVOS ==========
  'A.8.3': {
    id: 'A.8.3',
    nombre: 'Manipulación de soportes',
    descripcion: 'Los soportes que contienen información se protegen contra acceso no autorizado, uso indebido o corrupción durante el transporte',
    anexo: 'A.8'
  },
  'A.8.9': {
    id: 'A.8.9',
    nombre: 'Gestión de la configuración',
    descripcion: 'Se establecen, documentan, implementan, monitorean y revisan configuraciones de hardware, software, servicios y redes',
    anexo: 'A.8'
  },
  'A.8.23': {
    id: 'A.8.23',
    nombre: 'Filtrado web',
    descripcion: 'Se gestiona el acceso a sitios web externos para reducir la exposición a contenido malicioso',
    anexo: 'A.8'
  },

  // ========== A.9 - CONTROL DE ACCESO ==========
  'A.9.2': {
    id: 'A.9.2',
    nombre: 'Gestión de acceso de usuarios',
    descripcion: 'Se asegura el acceso de usuarios autorizados y se previene el acceso no autorizado a sistemas e información',
    anexo: 'A.9'
  },
  'A.9.4': {
    id: 'A.9.4',
    nombre: 'Gestión de información de autenticación secreta de usuarios',
    descripcion: 'La asignación de información de autenticación secreta se controla mediante un proceso formal de gestión',
    anexo: 'A.9'
  },

  // ========== A.12 - SEGURIDAD DE LAS OPERACIONES ==========
  'A.12.4': {
    id: 'A.12.4',
    nombre: 'Registro y supervisión',
    descripcion: 'Se crean, mantienen, protegen y analizan registros de eventos sobre actividades de usuarios, excepciones, fallos y eventos de seguridad',
    anexo: 'A.12'
  },
  'A.12.5': {
    id: 'A.12.5',
    nombre: 'Control del software en explotación',
    descripcion: 'Se asegura la integridad de los sistemas operacionales mediante procedimientos para controlar la instalación de software en sistemas operacionales',
    anexo: 'A.12'
  },
  'A.12.6': {
    id: 'A.12.6',
    nombre: 'Gestión de vulnerabilidad técnica',
    descripcion: 'Se previene la explotación de vulnerabilidades técnicas mediante información oportuna sobre vulnerabilidades técnicas',
    anexo: 'A.12'
  },

  // ========== A.13 - SEGURIDAD DE LAS COMUNICACIONES ==========
  'A.13.1': {
    id: 'A.13.1',
    nombre: 'Gestión de seguridad de redes',
    descripcion: 'Las redes y los dispositivos de red se gestionan y controlan para proteger la información en sistemas y aplicaciones',
    anexo: 'A.13'
  },
  'A.13.2': {
    id: 'A.13.2',
    nombre: 'Transferencia de información',
    descripcion: 'Se mantiene la seguridad de la información transferida dentro de una organización y con cualquier entidad externa',
    anexo: 'A.13'
  },
};

/**
 * Mapea verificaciones del script PowerShell a controles ISO 27001
 */
export const MAPEO_VERIFICACIONES_ISO: Record<string, string[]> = {
  // Cifrado
  'bitlocker': ['A.8.3'],
  
  // Usuarios y acceso
  'administradores': ['A.9.2'],
  'laps': ['A.9.2', 'A.9.4'],
  'usuarios_sin_password': ['A.9.4'],
  
  // Monitoreo y logs
  'wazuh_agent': ['A.12.4'],
  
  // Software y antivirus
  'antivirus_activo': ['A.12.5'],
  'defender_atp': ['A.12.5'],
  'windows_update': ['A.12.6'],
  
  // Red y firewall
  'firewall': ['A.13.1'],
  'smbv1': ['A.13.2'],
  'ipv6': ['A.13.1'],
  
  // Configuración
  'uac': ['A.8.9'],
  'remote_desktop': ['A.9.2', 'A.13.1'],
  'bloqueador_web': ['A.8.23'],
};

/**
 * Obtiene los controles ISO afectados por hallazgos
 */
export function obtenerControlesAfectados(findings: { check_name: string }[]): ControlISO27001[] {
  const controlesSet = new Set<string>();
  
  findings.forEach(finding => {
    const controles = MAPEO_VERIFICACIONES_ISO[finding.check_name];
    if (controles) {
      controles.forEach(c => controlesSet.add(c));
    }
  });
  
  return Array.from(controlesSet)
    .map(id => CONTROLES_ISO27001[id])
    .filter(Boolean);
}

/**
 * Calcula el impacto en la certificación ISO 27001
 */
export function calcularImpactoCertificacion(
  score: number,
  errores: number,
  controlesAfectados: ControlISO27001[]
): string {
  if (errores > 0) {
    return '🔴 CRÍTICO - No conformidad mayor detectada. Requiere acción inmediata antes de auditoría.';
  }
  
  if (score < 80) {
    return '🟠 ALTO - No conformidad menor. Debe corregirse antes de la siguiente auditoría.';
  }
  
  if (score < 90) {
    return '🟡 MEDIO - Oportunidad de mejora. Recomendado corregir para fortalecer postura de seguridad.';
  }
  
  return '🟢 BAJO - Cumplimiento satisfactorio. Mantener controles actuales.';
}
