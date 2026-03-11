// routes/analyze-server.ts - Endpoint para análisis de Windows Servers
// Versión 3.2 - Compatible con JSON generado por Hardening Compliance Check Servers v1.0

import { Router, Request, Response } from 'express';
import { ServerComplianceData } from '../utils/types';
import { generarAnalisisServidor } from '../generators/server';

const router = Router();

/**
 * POST /analyze-server
 * Analiza un servidor Windows (reemplaza lógica Gemini para servidores)
 * Entrada: ServerComplianceData (JSON generado por Hardening Compliance Check Servers v1.0)
 * Salida:  AnalysisResponse (misma estructura que /analyze-individual)
 */
router.post('/analyze-server', (req: Request, res: Response) => {
  try {
    const data: ServerComplianceData = req.body;

    // Validación básica
    if (!data.hostname) {
      return res.status(400).json({
        error:   'Datos inválidos',
        message: 'Se requiere campo hostname',
      });
    }

    if (data.compliance_score === undefined || data.compliance_score === null) {
      return res.status(400).json({
        error:   'Datos inválidos',
        message: 'Se requiere campo compliance_score',
      });
    }

    if (!data.checks || typeof data.checks !== 'object') {
      return res.status(400).json({
        error:   'Datos inválidos',
        message: 'Se requiere campo checks con las secciones de auditoría',
      });
    }

    // Generar análisis específico para servidor
    const analisis = generarAnalisisServidor(data);

    // Log
    const tipoMaq = data.es_maquina_virtual
      ? `VM (${data.tipo_virtualizacion || 'Virtual'})`
      : 'Servidor Físico';
    console.log(
      `[ANÁLISIS SERVIDOR] ${data.hostname} (${tipoMaq}) - Score: ${data.compliance_score}% - ` +
      `OK:${data.passed} WARN:${data.warnings} ERR:${data.errors} ` +
      `SO: ${data.sistema_operativo?.nombre || 'N/A'}`
    );

    res.json(analisis);

  } catch (error: any) {
    console.error('[ERROR] Análisis servidor:', error);
    res.status(500).json({
      error:   'Error al generar análisis de servidor',
      message: error.message,
    });
  }
});

export default router;
