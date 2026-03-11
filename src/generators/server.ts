// generators/server.ts - Análisis de Hardening para Windows Servers
// Versión 3.2 - Específico para servidores ISO 27001:2022 / ENS
// Compatible con ServerComplianceData (campo tipo_equipo = "SERVIDOR")

import { ServerComplianceData } from '../utils/types';
import { AnalysisResponse, Finding } from '../utils/types';

// ============================================================
// MAPEO ISO 27001:2022 PARA SERVIDORES
// (diferente de endpoints: sin BitLocker, con Zabbix/Veeam/RDP/TLS)
// ============================================================
const CONTROLES_ISO_SERVIDOR: Record<string, {
  codigo: string;
  nombre: string;
  control_ens: string;
  descripcion: string;
}> = {
  smb1:            { codigo: 'A.8.8',  nombre: 'Gestión de vulnerabilidades técnicas',   control_ens: 'op.exp.2',  descripcion: 'SMBv1 protocolo vulnerable' },
  tls_obsoleto:    { codigo: 'A.8.24', nombre: 'Uso de criptografía',                    control_ens: 'op.exp.11', descripcion: 'TLS 1.0/1.1 o SSL 3.0 activos' },
  tls12_faltante:  { codigo: 'A.8.24', nombre: 'Uso de criptografía',                    control_ens: 'op.exp.11', descripcion: 'TLS 1.2 no habilitado' },
  nla_rdp:         { codigo: 'A.8.5',  nombre: 'Autenticación segura',                   control_ens: 'op.acc.5',  descripcion: 'RDP sin NLA (Network Level Authentication)' },
  firewall:        { codigo: 'A.8.20', nombre: 'Seguridad de redes',                     control_ens: 'op.exp.10', descripcion: 'Firewall desactivado o mal configurado' },
  so_eol:          { codigo: 'A.8.8',  nombre: 'Gestión de vulnerabilidades técnicas',   control_ens: 'op.exp.2',  descripcion: 'SO sin soporte activo del fabricante' },
  actualizaciones: { codigo: 'A.8.8',  nombre: 'Gestión de vulnerabilidades técnicas',   control_ens: 'op.exp.4',  descripcion: 'Actualizaciones pendientes de instalar' },
  antivirus:       { codigo: 'A.8.7',  nombre: 'Protección contra malware',              control_ens: 'op.exp.6',  descripcion: 'ESET no instalado o no activo' },
  zabbix:          { codigo: 'A.8.16', nombre: 'Actividades de monitorización',          control_ens: 'op.mon.1',  descripcion: 'Zabbix Agent no instalado o detenido' },
  wazuh:           { codigo: 'A.8.15', nombre: 'Logging',                               control_ens: 'op.exp.9',  descripcion: 'Wazuh SIEM Agent no instalado' },
  veeam:           { codigo: 'A.8.13', nombre: 'Copias de seguridad',                   control_ens: 'op.cont.2', descripcion: 'Veeam Backup no detectado' },
  guest:           { codigo: 'A.8.2',  nombre: 'Derechos de acceso privilegiados',      control_ens: 'op.acc.2',  descripcion: 'Cuenta Invitado habilitada' },
  admins_exceso:   { codigo: 'A.8.2',  nombre: 'Derechos de acceso privilegiados',      control_ens: 'op.acc.4',  descripcion: 'Exceso de administradores locales' },
  politica_pass:   { codigo: 'A.5.17', nombre: 'Información de autenticación',          control_ens: 'op.acc.6',  descripcion: 'Política de contraseñas insuficiente' },
  auditoria:       { codigo: 'A.8.15', nombre: 'Logging',                               control_ens: 'op.mon.3',  descripcion: 'Directivas de auditoría no configuradas' },
  wsus:            { codigo: 'A.8.8',  nombre: 'Gestión de vulnerabilidades técnicas',   control_ens: 'op.exp.4',  descripcion: 'WSUS no configurado' },
  dominio:         { codigo: 'A.8.5',  nombre: 'Autenticación segura',                  control_ens: 'op.acc.1',  descripcion: 'Servidor no unido a dominio AD' },
  shares:          { codigo: 'A.8.20', nombre: 'Seguridad de redes',                    control_ens: 'op.exp.10', descripcion: 'Recursos compartidos no justificados' },
};

// ============================================================
// EXTRACTOR DE HALLAZGOS
// ============================================================
function extraerHallazgos(data: ServerComplianceData): Finding[] {
  const hallazgos: Finding[] = [];

  for (const seccion of Object.keys(data.checks || {})) {
    const seccionChecks = data.checks[seccion];
    for (const checkName of Object.keys(seccionChecks)) {
      const check = seccionChecks[checkName];
      if (check.estado === 'WARNING' || check.estado === 'ERROR') {
        hallazgos.push({
          seccion,
          check_name: checkName,
          estado: check.estado,
          criticidad: check.criticidad,
          detalle: check.detalle,
        });
      }
    }
  }

  // Ordenar: CRITICA > ALTA > MEDIA > BAJA, y ERROR antes de WARNING
  const ordenCrit = { CRITICA: 0, ALTA: 1, MEDIA: 2, BAJA: 3 };
  const ordenEst  = { ERROR: 0, WARNING: 1, OK: 2 };
  hallazgos.sort((a, b) => {
    const dc = ordenCrit[a.criticidad] - ordenCrit[b.criticidad];
    if (dc !== 0) return dc;
    return ordenEst[a.estado] - ordenEst[b.estado];
  });

  return hallazgos;
}

// ============================================================
// DETECTAR CONTROLES AFECTADOS
// ============================================================
function detectarControlesAfectados(
  hallazgos: Finding[],
  data: ServerComplianceData
): AnalysisResponse['mapeo_iso27001']['controles_afectados'] {

  const controlesMap = new Map<string, typeof CONTROLES_ISO_SERVIDOR[string] & {
    estado: 'NO_CONFORME' | 'PARCIAL' | 'CONFORME';
    hallazgo: string;
  }>();

  // Análisis por hallazgo
  for (const h of hallazgos) {
    const key = h.check_name.toLowerCase();
    let controlKey: string | null = null;

    if (key.includes('smbv1'))                 controlKey = 'smb1';
    else if (key.includes('tls_1_0') || key.includes('tls_1_1') || key.includes('ssl3')) controlKey = 'tls_obsoleto';
    else if (key.includes('tls_1_2'))          controlKey = 'tls12_faltante';
    else if (key.includes('nla'))              controlKey = 'nla_rdp';
    else if (key.includes('firewall'))         controlKey = 'firewall';
    else if (key.includes('version_so'))       controlKey = 'so_eol';
    else if (key.includes('actualizaciones'))  controlKey = 'actualizaciones';
    else if (key.includes('eset'))             controlKey = 'antivirus';
    else if (key.includes('zabbix'))           controlKey = 'zabbix';
    else if (key.includes('wazuh'))            controlKey = 'wazuh';
    else if (key.includes('veeam'))            controlKey = 'veeam';
    else if (key.includes('invitado') || key.includes('guest'))  controlKey = 'guest';
    else if (key.includes('administradores_locales'))             controlKey = 'admins_exceso';
    else if (key.includes('contrasena') || key.includes('password')) controlKey = 'politica_pass';
    else if (key.includes('auditoria') || key.includes('audit'))     controlKey = 'auditoria';
    else if (key.includes('wsus'))             controlKey = 'wsus';
    else if (key.includes('dominio'))          controlKey = 'dominio';
    else if (key.includes('compartidos') || key.includes('share')) controlKey = 'shares';

    if (controlKey && CONTROLES_ISO_SERVIDOR[controlKey]) {
      const ctrl = CONTROLES_ISO_SERVIDOR[controlKey];
      const estadoCtrl = h.estado === 'ERROR' ? 'NO_CONFORME' : 'PARCIAL';

      if (!controlesMap.has(ctrl.codigo) ||
          (estadoCtrl === 'NO_CONFORME' && controlesMap.get(ctrl.codigo)!.estado !== 'NO_CONFORME')) {
        controlesMap.set(ctrl.codigo, {
          ...ctrl,
          estado: estadoCtrl,
          hallazgo: h.detalle,
        });
      }
    }
  }

  // Añadir controles en CONFORME si no tienen hallazgos
  const controlesConformes: string[] = [];
  if (!controlesMap.has('A.8.8')  && data.compliance_score >= 80) controlesConformes.push('A.8.8');
  if (!controlesMap.has('A.8.20') && data.compliance_score >= 80) controlesConformes.push('A.8.20');
  if (!controlesMap.has('A.8.5')  && data.compliance_score >= 80) controlesConformes.push('A.8.5');

  const resultado = Array.from(controlesMap.values()).map(c => ({
    codigo:               c.codigo,
    nombre:               c.nombre,
    estado:               c.estado as 'NO_CONFORME' | 'PARCIAL' | 'CONFORME',
    hallazgo_relacionado: c.hallazgo,
    control_ens:          c.control_ens,
  }));

  return resultado.slice(0, 8); // máx 8 controles
}

// ============================================================
// GENERADOR DE RIESGOS PARA SERVIDORES
// ============================================================
function generarRiesgosServidor(
  hallazgos: Finding[],
  data: ServerComplianceData
): AnalysisResponse['riesgos'] {

  const riesgos: AnalysisResponse['riesgos'] = [];
  const esVM = data.es_maquina_virtual || false;

  // Riesgo 1: SO sin soporte o TLS obsoleto (CRÍTICO para servidores)
  const soEol    = hallazgos.find(h => h.check_name.toLowerCase().includes('version_so') && h.estado === 'ERROR');
  const tlsViejo = hallazgos.find(h => (h.check_name.includes('TLS_1_0') || h.check_name.includes('SSL3')) && h.estado === 'ERROR');
  const nlaFallo = hallazgos.find(h => h.check_name.includes('NLA'));

  if (soEol) {
    riesgos.push({
      descripcion: `Sistema operativo ${data.sistema_operativo?.nombre || 'desconocido'} sin soporte activo del fabricante. Sin parches de seguridad disponibles.`,
      criticidad:  'ALTA',
      impacto:     'Vulnerabilidades sin parchear pueden permitir escalada de privilegios, ransomware o compromiso total del servidor',
      control_iso27001: 'A.8.8 - Gestión de vulnerabilidades técnicas',
      control_ens:      'op.exp.2',
      evidencia:        soEol.detalle,
    });
  } else if (tlsViejo) {
    riesgos.push({
      descripcion: 'Protocolos TLS/SSL obsoletos activos (TLS 1.0 o SSL 3.0). Comunicaciones cifradas con algoritmos vulnerables.',
      criticidad:  'ALTA',
      impacto:     'Ataques POODLE/BEAST pueden descifrar comunicaciones. Incumplimiento de requisitos PCI-DSS e ISO 27001 A.8.24',
      control_iso27001: 'A.8.24 - Uso de criptografía',
      control_ens:      'op.exp.11',
      evidencia:        tlsViejo.detalle,
    });
  } else {
    const hallazgoCritico = hallazgos.find(h => h.criticidad === 'CRITICA');
    if (hallazgoCritico) {
      riesgos.push({
        descripcion: `Hallazgo crítico detectado: ${hallazgoCritico.check_name.replace(/_/g, ' ')}`,
        criticidad:  'ALTA',
        impacto:     'Compromiso potencial de la integridad y disponibilidad del servidor',
        control_iso27001: 'A.8.8 - Gestión de vulnerabilidades técnicas',
        control_ens:      'op.exp.2',
        evidencia:        hallazgoCritico.detalle,
      });
    }
  }

  // Riesgo 2: Acceso remoto sin autenticación robusta (NLA/RDP)
  if (nlaFallo) {
    riesgos.push({
      descripcion: 'RDP sin Network Level Authentication (NLA). Acceso remoto con autenticación débil.',
      criticidad:  'ALTA',
      impacto:     'Ataques de fuerza bruta, credential stuffing y BlueKeep pueden comprometer el servidor remotamente',
      control_iso27001: 'A.8.5 - Autenticación segura',
      control_ens:      'op.acc.5',
      evidencia:        nlaFallo.detalle,
    });
  } else {
    // Buscar segundo riesgo relevante
    const smb1  = hallazgos.find(h => h.check_name.includes('SMBv1') && h.estado === 'ERROR');
    const noAV  = hallazgos.find(h => h.check_name.includes('ESET') && h.estado === 'ERROR');
    const noZab = hallazgos.find(h => h.check_name.includes('Zabbix') && h.estado === 'ERROR');

    if (smb1) {
      riesgos.push({
        descripcion: 'SMBv1 habilitado en servidor. Protocolo vulnerable a WannaCry/NotPetya y EternalBlue.',
        criticidad:  'ALTA',
        impacto:     'Propagación lateral de ransomware en la red, cifrado masivo de datos y servidores',
        control_iso27001: 'A.8.8 - Gestión de vulnerabilidades técnicas',
        control_ens:      'op.exp.2',
        evidencia:        smb1.detalle,
      });
    } else if (noAV) {
      riesgos.push({
        descripcion: 'Servidor sin protección antivirus corporativa (ESET no instalado o detenido).',
        criticidad:  'ALTA',
        impacto:     'Sin detección de malware, ransomware o actividad maliciosa en el servidor',
        control_iso27001: 'A.8.7 - Protección contra malware',
        control_ens:      'op.exp.6',
        evidencia:        noAV.detalle,
      });
    } else if (noZab) {
      riesgos.push({
        descripcion: 'Servidor sin monitorización Zabbix activa. Sin visibilidad de rendimiento y disponibilidad.',
        criticidad:  'MEDIA',
        impacto:     'Fallos no detectados, degradación de servicio sin alertas, incumplimiento ISO 27001 A.8.16',
        control_iso27001: 'A.8.16 - Actividades de monitorización',
        control_ens:      'op.mon.1',
        evidencia:        noZab.detalle,
      });
    }
  }

  // Riesgo 3: Backup y continuidad
  const noVeeam = hallazgos.find(h => h.check_name.includes('Veeam'));
  const noAudit = hallazgos.find(h => h.check_name.includes('Auditoria'));
  const actPend = hallazgos.find(h => h.check_name.includes('Actualizaciones') && h.estado === 'ERROR');

  if (noVeeam && noVeeam.estado !== 'OK') {
    riesgos.push({
      descripcion: 'Veeam Backup no detectado o no activo. Continuidad del negocio en riesgo.',
      criticidad:  'MEDIA',
      impacto:     'Sin backup garantizado: pérdida de datos irrecuperable en caso de fallo, ransomware o desastre',
      control_iso27001: 'A.8.13 - Copias de seguridad',
      control_ens:      'op.cont.2',
      evidencia:        noVeeam.detalle,
    });
  } else if (actPend) {
    riesgos.push({
      descripcion: `Servidor con más de 5 actualizaciones de seguridad pendientes de instalar.`,
      criticidad:  'ALTA',
      impacto:     'Vulnerabilidades conocidas sin parchear. Superficie de ataque ampliada.',
      control_iso27001: 'A.8.8 - Gestión de vulnerabilidades técnicas',
      control_ens:      'op.exp.4',
      evidencia:        actPend.detalle,
    });
  } else if (noAudit) {
    riesgos.push({
      descripcion: 'Directivas de auditoría no configuradas. Sin trazabilidad de eventos de seguridad.',
      criticidad:  'MEDIA',
      impacto:     'Incapacidad de detectar intrusiones, cambios no autorizados o fugas de datos post-incidente',
      control_iso27001: 'A.8.15 - Logging',
      control_ens:      'op.mon.3',
      evidencia:        noAudit?.detalle || 'Directivas de auditoría no configuradas',
    });
  } else if (hallazgos.length > 0) {
    const h = hallazgos[Math.min(2, hallazgos.length - 1)];
    riesgos.push({
      descripcion: `${h.seccion.replace(/_/g, ' ')}: ${h.check_name.replace(/_/g, ' ')}`,
      criticidad:  h.criticidad === 'CRITICA' ? 'ALTA' : h.criticidad as 'ALTA' | 'MEDIA' | 'BAJA',
      impacto:     'Incumplimiento de políticas de seguridad ISO 27001 para servidores corporativos',
      control_iso27001: 'A.8.8 - Gestión de vulnerabilidades técnicas',
      control_ens:      'op.exp.2',
      evidencia:        h.detalle,
    });
  }

  // Garantizar exactamente 3 riesgos
  while (riesgos.length < 3) {
    const idx = riesgos.length;
    const defaults = [
      {
        descripcion: `Score de cumplimiento ${data.compliance_score}% por debajo del objetivo 90%`,
        criticidad: 'MEDIA' as const,
        impacto:    'Incumplimiento parcial de controles ISO 27001 para servidores corporativos',
        control_iso27001: 'A.5.1 - Políticas para la seguridad de la información',
        control_ens: 'org.1',
        evidencia:  `Score actual: ${data.compliance_score}%, objetivo: 90%`,
      },
      {
        descripcion: 'Revisar configuración de acceso remoto y gestión de identidades en el servidor',
        criticidad: 'BAJA' as const,
        impacto:    'Posibles brechas de control de acceso no detectadas en el servidor',
        control_iso27001: 'A.8.5 - Autenticación segura',
        control_ens: 'op.acc.1',
        evidencia:  'Revisión periódica de controles de acceso recomendada',
      },
      {
        descripcion: 'Verificar configuración de red y protocolos de comunicación del servidor',
        criticidad: 'BAJA' as const,
        impacto:    'Protocolos inseguros o configuraciones de red inadecuadas',
        control_iso27001: 'A.8.20 - Seguridad de redes',
        control_ens: 'op.exp.10',
        evidencia:  'Revisar IPv6, shares, y configuración de red',
      },
    ];
    riesgos.push(defaults[idx] || defaults[0]);
  }

  return riesgos.slice(0, 3);
}

// ============================================================
// GENERADOR DE ACCIONES RECOMENDADAS PARA SERVIDORES
// ============================================================
function generarAccionesServidor(
  hallazgos: Finding[],
  data: ServerComplianceData
): AnalysisResponse['acciones_recomendadas'] {

  const acciones: AnalysisResponse['acciones_recomendadas'] = [];

  // Acción: Deshabilitar TLS 1.0/1.1 y SSL 3.0
  const tlsHallazgo = hallazgos.find(h =>
    (h.check_name.includes('TLS_1_0') || h.check_name.includes('TLS_1_1') || h.check_name.includes('SSL3')) &&
    (h.estado === 'ERROR' || h.estado === 'WARNING'));
  if (tlsHallazgo) {
    acciones.push({
      accion:       'Deshabilitar protocolos TLS 1.0, TLS 1.1 y SSL 3.0 en el registro del servidor',
      prioridad:    'ALTA',
      tipo:         'Hardening de red',
      herramienta:  'Registry Editor / PowerShell / IIS Crypto',
      comando:      'Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server" -Name Enabled -Value 0',
      tiempo_estimado: '30 minutos',
      responsable_sugerido: 'Administrador de Sistemas',
      documentacion_iso: 'ISO 27001:2022 A.8.24 - Uso de criptografía / ENS op.exp.11',
    });
  }

  // Acción: Habilitar NLA en RDP
  const nlaHallazgo = hallazgos.find(h => h.check_name.includes('NLA') && h.estado === 'ERROR');
  if (nlaHallazgo) {
    acciones.push({
      accion:       'Habilitar Network Level Authentication (NLA) en las conexiones RDP del servidor',
      prioridad:    'ALTA',
      tipo:         'Endurecimiento acceso remoto',
      herramienta:  'PowerShell / Group Policy',
      comando:      'Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name UserAuthenticationRequired -Value 1',
      tiempo_estimado: '15 minutos',
      responsable_sugerido: 'Administrador de Sistemas',
      documentacion_iso: 'ISO 27001:2022 A.8.5 - Autenticación segura / ENS op.acc.5',
    });
  }

  // Acción: Instalar / reactivar Zabbix Agent
  const zabbixHallazgo = hallazgos.find(h => h.check_name.includes('Zabbix'));
  if (zabbixHallazgo) {
    acciones.push({
      accion:       data.zabbix_detallado?.instalado
        ? 'Reactivar servicio Zabbix Agent en el servidor (Start-Service "Zabbix Agent")'
        : 'Instalar Zabbix Agent en el servidor y configurar conexión con servidor Zabbix corporativo',
      prioridad:    'ALTA',
      tipo:         'Monitorización',
      herramienta:  'Zabbix Agent MSI / Action1 RMM',
      comando:      data.zabbix_detallado?.instalado
        ? 'Start-Service "Zabbix Agent"; Set-Service "Zabbix Agent" -StartupType Automatic'
        : 'msiexec /i zabbix_agent.msi /qn SERVER=<IP_ZABBIX> SERVERACTIVE=<IP_ZABBIX>',
      tiempo_estimado: data.zabbix_detallado?.instalado ? '5 minutos' : '20 minutos',
      responsable_sugerido: 'Administrador de Sistemas / IT Ops',
      documentacion_iso: 'ISO 27001:2022 A.8.16 - Actividades de monitorización / ENS op.mon.1',
    });
  }

  // Acción: Instalar / reactivar ESET
  const esetHallazgo = hallazgos.find(h => h.check_name.includes('ESET') && h.estado === 'ERROR');
  if (esetHallazgo) {
    acciones.push({
      accion:       data.proteccion_malware_instalado
        ? 'Reactivar servicio ESET en el servidor (ekrn / EraAgentSvc)'
        : 'Instalar ESET Server Security y conectar con ESET PROTECT (management center)',
      prioridad:    'ALTA',
      tipo:         'Protección malware',
      herramienta:  'ESET Server Security / ESET PROTECT Console',
      tiempo_estimado: '30 minutos',
      responsable_sugerido: 'Administrador de Sistemas',
      documentacion_iso: 'ISO 27001:2022 A.8.7 - Protección contra malware / ENS op.exp.6',
    });
  }

  // Acción: Deshabilitar SMBv1
  const smb1Hallazgo = hallazgos.find(h => h.check_name.includes('SMBv1') && h.estado === 'ERROR');
  if (smb1Hallazgo) {
    acciones.push({
      accion:       'Deshabilitar protocolo SMBv1 en el servidor',
      prioridad:    'ALTA',
      tipo:         'Hardening de red',
      herramienta:  'PowerShell',
      comando:      'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Set-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" SMB1 -Type DWORD -Value 0',
      tiempo_estimado: '10 minutos (requiere reinicio)',
      responsable_sugerido: 'Administrador de Sistemas',
      documentacion_iso: 'ISO 27001:2022 A.8.8 - Gestión de vulnerabilidades técnicas / ENS op.exp.2',
    });
  }

  // Acción: Configurar WSUS
  const wsusHallazgo = hallazgos.find(h => h.check_name.includes('WSUS'));
  if (wsusHallazgo && acciones.length < 5) {
    acciones.push({
      accion:       'Configurar servidor WSUS en el servidor para gestión centralizada de actualizaciones',
      prioridad:    'MEDIA',
      tipo:         'Gestión de parches',
      herramienta:  'Group Policy (GPO) / Registry',
      tiempo_estimado: '30 minutos',
      responsable_sugerido: 'Administrador de Sistemas',
      documentacion_iso: 'ISO 27001:2022 A.8.8 - Gestión de vulnerabilidades técnicas / ENS op.exp.4',
    });
  }

  // Acción: Configurar directivas de auditoría
  const auditHallazgo = hallazgos.find(h => h.check_name.includes('Auditoria') && h.criticidad !== 'BAJA');
  if (auditHallazgo && acciones.length < 5) {
    acciones.push({
      accion:       'Configurar directivas de auditoría avanzadas en el servidor (logon, object access, policy change)',
      prioridad:    'MEDIA',
      tipo:         'Auditoría y logging',
      herramienta:  'auditpol / Group Policy',
      comando:      'auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable; auditpol /set /category:"Account Management" /success:enable /failure:enable',
      tiempo_estimado: '30 minutos',
      responsable_sugerido: 'Administrador de Sistemas',
      documentacion_iso: 'ISO 27001:2022 A.8.15 - Logging / ENS op.mon.3',
    });
  }

  // Acción: Instalar Wazuh
  const wazuhHallazgo = hallazgos.find(h => h.check_name.includes('Wazuh') && !data.wazuh_detallado?.instalado);
  if (wazuhHallazgo && acciones.length < 5) {
    acciones.push({
      accion:       'Instalar Wazuh Agent y conectar con servidor Wazuh SIEM corporativo',
      prioridad:    'MEDIA',
      tipo:         'SIEM / Detección de intrusiones',
      herramienta:  'Wazuh Agent / Action1 RMM',
      tiempo_estimado: '30 minutos',
      responsable_sugerido: 'Equipo de Seguridad',
      documentacion_iso: 'ISO 27001:2022 A.8.15 - Logging / ENS op.exp.9',
    });
  }

  // Acción: Verificar Veeam Backup
  const veeamHallazgo = hallazgos.find(h => h.check_name.includes('Veeam'));
  if (veeamHallazgo && acciones.length < 5) {
    acciones.push({
      accion:       'Verificar y restaurar configuración de Veeam Backup para este servidor',
      prioridad:    'ALTA',
      tipo:         'Continuidad de negocio / Backup',
      herramienta:  'Veeam Backup & Replication Console',
      tiempo_estimado: '1-2 horas',
      responsable_sugerido: 'Administrador de Sistemas',
      documentacion_iso: 'ISO 27001:2022 A.8.13 - Copias de seguridad / ENS op.cont.2',
    });
  }

  // Rellenar hasta 5 acciones con acciones genéricas relevantes
  const accionesGenericas = [
    {
      accion:       'Aplicar actualizaciones de seguridad pendientes de Windows Server',
      prioridad:    'ALTA' as const,
      tipo:         'Gestión de parches',
      herramienta:  'Windows Server Update Services (WSUS) / Windows Update',
      tiempo_estimado: '1-2 horas',
      responsable_sugerido: 'Administrador de Sistemas',
      documentacion_iso: 'ISO 27001:2022 A.8.8 / ENS op.exp.4',
    },
    {
      accion:       'Revisar y reducir miembros del grupo Administradores locales',
      prioridad:    'MEDIA' as const,
      tipo:         'Control de acceso',
      herramienta:  'PowerShell / Active Directory',
      tiempo_estimado: '30 minutos',
      responsable_sugerido: 'Administrador de Sistemas',
      documentacion_iso: 'ISO 27001:2022 A.8.2 / ENS op.acc.4',
    },
    {
      accion:       'Configurar timeout de sesiones RDP inactivas (máx. 60 minutos)',
      prioridad:    'BAJA' as const,
      tipo:         'Control de acceso',
      herramienta:  'Group Policy / Registry',
      tiempo_estimado: '15 minutos',
      responsable_sugerido: 'Administrador de Sistemas',
      documentacion_iso: 'ISO 27001:2022 A.8.5 / ENS op.acc.5',
    },
    {
      accion:       'Aumentar tamaño del registro de eventos Security a mínimo 128MB',
      prioridad:    'MEDIA' as const,
      tipo:         'Auditoría y logging',
      herramienta:  'PowerShell / Event Viewer',
      comando:      'wevtutil sl Security /ms:134217728',
      tiempo_estimado: '10 minutos',
      responsable_sugerido: 'Administrador de Sistemas',
      documentacion_iso: 'ISO 27001:2022 A.8.15 - Logging / ENS op.mon.3',
    },
    {
      accion:       'Deshabilitar IPv6 en adaptadores de red si no es necesario',
      prioridad:    'BAJA' as const,
      tipo:         'Hardening de red',
      herramienta:  'PowerShell / Network Adapter Settings',
      tiempo_estimado: '15 minutos',
      responsable_sugerido: 'Administrador de Sistemas',
      documentacion_iso: 'ISO 27001:2022 A.8.20 - Seguridad de redes / ENS op.exp.10',
    },
  ];

  let idxGenerica = 0;
  while (acciones.length < 5 && idxGenerica < accionesGenericas.length) {
    acciones.push(accionesGenericas[idxGenerica]);
    idxGenerica++;
  }

  return acciones.slice(0, 5);
}

// ============================================================
// FUNCIÓN PRINCIPAL: generarAnalisisServidor
// ============================================================
export function generarAnalisisServidor(data: ServerComplianceData): AnalysisResponse {
  const hallazgos = extraerHallazgos(data);
  const fechaHoy  = new Date().toISOString().split('T')[0];

  // Calcular días hasta próxima revisión (30 días para servidores)
  const proximaRevision = new Date();
  proximaRevision.setDate(proximaRevision.getDate() + 30);

  // Score y métricas
  const score          = Math.round(data.compliance_score);
  const errores        = data.errors || 0;
  const avisos         = data.warnings || 0;
  const ok             = data.passed || 0;
  const total          = data.total_checks || (ok + avisos + errores);
  const esVM           = data.es_maquina_virtual || false;
  const tipoMaq        = esVM ? `VM (${data.tipo_virtualizacion || 'Virtual'})` : 'Servidor Físico';

  // Categoría del score
  const categoria =
    score >= 90 ? 'ALTO cumplimiento'    :
    score >= 75 ? 'MEDIO cumplimiento'   :
    score >= 50 ? 'BAJO cumplimiento'    :
                  'CRÍTICO - Acción urgente requerida';

  // Resumen ejecutivo enfocado en servidores
  const soInfo = data.sistema_operativo;
  const soNombre = soInfo?.nombre || 'Windows Server';
  const soSoporte = soInfo?.soporte_activo !== false;
  const hayHallazgosCriticos = hallazgos.some(h => h.criticidad === 'CRITICA');
  const zabbixOK   = data.zabbix_detallado?.funcional || false;
  const veeamOK    = data.veeam_detallado?.funcional  || false;
  const esetActivo = hallazgos.find(h => h.check_name.includes('ESET')) === undefined;

  const resumen_ejecutivo = [
    `Auditoría de hardening del servidor ${data.hostname} (${tipoMaq}) ejecutada el ${fechaHoy}.`,
    `Sistema operativo: ${soNombre}${soSoporte ? ' (soporte activo)' : ' ⚠️ SIN SOPORTE - RIESGO CRÍTICO'}.`,
    `Score de cumplimiento ISO 27001: ${score}% — ${categoria}.`,
    `Se identificaron ${errores} errores críticos y ${avisos} advertencias de un total de ${total} controles auditados.`,
    hayHallazgosCriticos
      ? `⚠️ ATENCIÓN: Existen hallazgos de criticidad CRÍTICA que requieren acción inmediata.`
      : `No se detectaron hallazgos de criticidad crítica en esta auditoría.`,
    `Monitorización Zabbix: ${zabbixOK ? 'Activa' : 'NO ACTIVA - Servidor sin monitorización'}.`,
    `Backup Veeam: ${veeamOK ? 'Activo' : 'NO DETECTADO - Verificar protección de backup'}.`,
    `Antivirus ESET: ${esetActivo ? 'Activo' : 'NO ACTIVO - Servidor sin protección AV corporativa'}.`,
    score >= 90
      ? `El servidor cumple con los requisitos mínimos de seguridad ISO 27001 para infraestructura crítica.`
      : `Se requiere plan de remediación para alcanzar el objetivo de 90% de cumplimiento.`,
  ].join(' ');

  // Controles ISO afectados
  const controlesAfectados = detectarControlesAfectados(hallazgos, data);

  // Impacto en certificación
  const ctrlNoCon  = controlesAfectados.filter(c => c.estado === 'NO_CONFORME').length;
  const ctrlParc   = controlesAfectados.filter(c => c.estado === 'PARCIAL').length;
  const impactoCert =
    ctrlNoCon > 3
      ? `ALTO: ${ctrlNoCon} controles no conformes y ${ctrlParc} parciales. Riesgo de no superar auditoría ISO 27001 sin remediación.`
      : ctrlNoCon > 0
      ? `MEDIO: ${ctrlNoCon} control(es) no conforme(s). Requiere plan de acción documentado antes de auditoría.`
      : ctrlParc > 2
      ? `BAJO-MEDIO: ${ctrlParc} controles parciales. Mejorar controles para consolidar certificación.`
      : 'BAJO: Conformidad general alta. Mantener controles y revisar periódicamente.';

  const reqPendientes =
    errores > 0
      ? `${errores} no conformidades a corregir: revisar ${hallazgos.filter(h => h.estado === 'ERROR').slice(0, 3).map(h => h.check_name.replace(/_/g, ' ')).join(', ')}`
      : avisos > 0
      ? `${avisos} observaciones de mejora: priorizar ${hallazgos.filter(h => h.estado === 'WARNING').slice(0, 3).map(h => h.check_name.replace(/_/g, ' ')).join(', ')}`
      : 'Sin requisitos pendientes críticos. Mantener monitorización continua.';

  // Riesgos (3)
  const riesgos = generarRiesgosServidor(hallazgos, data);

  // Acciones (5)
  const acciones = generarAccionesServidor(hallazgos, data);

  // Métricas
  const gapAbsoluto = Math.max(0, 90 - score);
  const tiempoRem   =
    gapAbsoluto === 0  ? 'Score objetivo alcanzado' :
    gapAbsoluto <= 10  ? '1-2 semanas (ajustes menores)' :
    gapAbsoluto <= 20  ? '2-4 semanas (remediación moderada)' :
    gapAbsoluto <= 35  ? '1-2 meses (remediación significativa)' :
                         '2-4 meses (plan de hardening completo)';

  // Indicadores clave para servidores
  const indicadores = [
    `Score compliance: ${score}%`,
    `Zabbix Agent: ${zabbixOK ? 'Activo' : 'INACTIVO'}`,
    `Veeam Backup: ${veeamOK ? 'Activo' : 'NO DETECTADO'}`,
    `ESET AV: ${esetActivo ? 'Activo' : 'INACTIVO'}`,
    `TLS 1.2: ${data.tls_detallado?.tls12_habilitado !== false ? 'Habilitado' : 'DESHABILITADO'}`,
  ];

  const tendencia: 'MEJORA' | 'ESTABLE' | 'DETERIORO' | 'DESCONOCIDA' =
    score >= 85 ? 'ESTABLE' :
    score >= 70 ? 'MEJORA'  :
    errores > 3 ? 'DETERIORO' : 'DESCONOCIDA';

  const comentariosSeg =
    score >= 90
      ? `Servidor ${data.hostname} en buen estado de seguridad. Revisión periódica mensual recomendada. Mantener agentes de monitorización activos.`
      : score >= 75
      ? `Servidor ${data.hostname} requiere atención en ${errores} errores detectados. Priorizar TLS, NLA y monitorización antes de próxima auditoría.`
      : `Servidor ${data.hostname} con score bajo (${score}%). Plan de hardening urgente necesario. Escalar a responsable de sistemas.`;

  return {
    hostname:         data.hostname,
    fecha_analisis:   new Date().toISOString(),
    compliance_score: score,
    score:            score,
    resumen_ejecutivo,

    mapeo_iso27001: {
      controles_afectados:  controlesAfectados,
      impacto_certificacion: impactoCert,
      requisitos_pendientes: reqPendientes,
    },

    riesgos,
    acciones_recomendadas: acciones,

    metricas_cumplimiento: {
      score_actual:               score,
      score_objetivo:             90,
      gap_critico:                gapAbsoluto > 0 ? `${gapAbsoluto}% por debajo del objetivo 90%` : 'Objetivo alcanzado',
      tiempo_remediacion_estimado: tiempoRem,
      controles_ok:               ok,
      controles_fallo:            avisos + errores,
    },

    seguimiento: {
      proxima_revision:    proximaRevision.toISOString().split('T')[0],
      indicadores_clave:   indicadores,
      tendencia,
      comentarios:         comentariosSeg,
    },
  };
}
