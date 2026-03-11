// server.ts - Servidor principal Express

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import analyzeServerRoutes from './routes/analyze-server';
import analyzeRoutes from './routes/analyze';

const app = express();
const PORT = process.env.PORT || 3000;

// ========== MIDDLEWARES ==========

// Seguridad
app.use(helmet());

// CORS - Permitir solo N8N en producción
const corsOptions = {
  origin: process.env.NODE_ENV === 'production'
    ? ['http://n8n:5678', 'http://localhost:5678', 'http://hardening-analyzer:3000']
    : '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// Compresión
app.use(compression());

// Body parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use((req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
  });
  next();
});

// ========== RUTAS ==========

// Health check
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    version: '3.2.0',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Root
app.get('/', (req: Request, res: Response) => {
  res.json({
    name: 'HARDENING ANALYZER API',
    version: '3.2.0',
    description: 'Analizador de Auditoría de Hardening ISO 27001 para Sisteplant',
    endpoints: {
      health: 'GET /health',
      analyzeIndividual: 'POST /analyze-individual',
      analyzeGlobal: 'POST /analyze-global',
      analyzeServer: 'POST /analyze-server'
    },
    status: 'running'
  });
});

// Rutas de análisis
app.use('/', analyzeRoutes);
app.use('/', analyzeServerRoutes);

// ========== ERROR HANDLERS ==========

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    error: 'Endpoint no encontrado',
    path: req.path,
    method: req.method
  });
});

// Error handler global
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('[ERROR GLOBAL]', err);
  res.status(500).json({
    error: 'Error interno del servidor',
    message: process.env.NODE_ENV === 'production' ? 'Error procesando solicitud' : err.message
  });
});

// ========== INICIO DEL SERVIDOR ==========

const server = app.listen(PORT, () => {
  console.log('');
  console.log('='.repeat(60));
  console.log('🔒 HARDENING ANALYZER API');
  console.log('='.repeat(60));
  console.log(`✅ Servidor corriendo en puerto ${PORT}`);
  console.log(`🌍 Modo: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🕐 Iniciado: ${new Date().toISOString()}`);
  console.log('');
  console.log('📡 Endpoints disponibles:');
  console.log(`   GET  http://localhost:${PORT}/health`);
  console.log(`   POST http://localhost:${PORT}/analyze-individual`);
  console.log(`   POST http://localhost:${PORT}/analyze-global`);
  console.log('='.repeat(60));
  console.log('');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('⚠️  SIGTERM recibido, cerrando servidor...');
  server.close(() => {
    console.log('✅ Servidor cerrado correctamente');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('⚠️  SIGINT recibido, cerrando servidor...');
  server.close(() => {
    console.log('✅ Servidor cerrado correctamente');
    process.exit(0);
  });
});

export default app;
