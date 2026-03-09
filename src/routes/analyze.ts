// routes/analyze.ts - Endpoints para N8N

import { Router, Request, Response } from 'express';
import { ComplianceData, GlobalAnalysisRequest } from '../utils/types';
import { generarAnalisisIndividual, generarReporteGlobalHTML } from '../generators/html';

const router = Router();

/**
 * POST /analyze-individual
 * Analiza un equipo individual (reemplaza Gemini individual)
 */
router.post('/analyze-individual', (req: Request, res: Response) => {
  try {
    const data: ComplianceData = req.body;
    
    // Validación básica
    if (!data.hostname || !data.compliance_score) {
      return res.status(400).json({
        error: 'Datos inválidos',
        message: 'Se requiere hostname y compliance_score'
      });
    }
    
    // Generar análisis
    const analisis = generarAnalisisIndividual(data);
    
    // Log para debugging
    console.log(`[ANÁLISIS INDIVIDUAL] ${data.hostname} - Score: ${data.compliance_score}%`);
    
    // Retornar análisis
    res.json(analisis);
    
  } catch (error: any) {
    console.error('[ERROR] Análisis individual:', error);
    res.status(500).json({
      error: 'Error al generar análisis',
      message: error.message
    });
  }
});

/**
 * POST /analyze-global
 * Genera reporte HTML consolidado (reemplaza Gemini global)
 */
router.post('/analyze-global', (req: Request, res: Response) => {
  try {
    const request: GlobalAnalysisRequest = req.body;
    
    // Validación básica
    if (!request.equipos || !Array.isArray(request.equipos) || request.equipos.length === 0) {
      return res.status(400).json({
        error: 'Datos inválidos',
        message: 'Se requiere array de equipos no vacío'
      });
    }
    
    // Generar reporte global
    const resultado = generarReporteGlobalHTML(
      request.equipos,
      request.fecha_analisis || new Date().toISOString()
    );
    
    // Log para debugging
    console.log(`[ANÁLISIS GLOBAL] ${resultado.metricas.total_equipos} equipos - Score promedio: ${resultado.metricas.score_promedio}%`);
    
    // Retornar HTML y métricas
    res.json(resultado);
    
  } catch (error: any) {
    console.error('[ERROR] Análisis global:', error);
    res.status(500).json({
      error: 'Error al generar reporte global',
      message: error.message
    });
  }
});

export default router;
