# 🔒 Hardening Analyzer

**Analizador de Auditoría de Hardening ISO 27001 para Sisteplant**

Reemplazo de Gemini AI con lógica determinista, controles ISO 27001 oficiales verificados y sin límites de tokens.

---

## 🎯 ¿QUÉ ES ESTO?

Sistema de análisis automático para auditorías de hardening Windows basadas en ISO 27001 y ENS.

**Reemplaza:**
- ❌ Gemini AI (cuesta $15-30/mes, falla con 30+ equipos, puede inventar controles)

**Con:**
- ✅ Lógica TypeScript determinista (gratis, procesa 300+ equipos, controles oficiales)

---

## ✨ CARACTERÍSTICAS

### 🎨 Análisis Individual
- Análisis detallado por equipo crítico
- Mapeo a controles ISO 27001:2022 oficiales
- Resumen ejecutivo claro
- Riesgos principales identificados
- Acciones recomendadas con prioridades

### 📊 Reporte Global HTML
- Dashboard visual consolidado
- Métricas de cumplimiento claras
- Tabla de equipos ordenada
- Código de colores intuitivo (🟢🟡🔴)
- Sin confusión en porcentajes

### 🔐 Controles ISO 27001
- **Hardcodeados** desde ISO 27001:2022 Anexo A
- **Verificados** contra el estándar oficial
- **NO inventados** - nunca alucina controles

---

## 🚀 VENTAJAS VS GEMINI

| Aspecto | Gemini | Hardening Analyzer |
|---------|--------|-------------------|
| **Coste** | $15-30/mes | **$0** |
| **Límite equipos** | ~30 (tokens) | **Ilimitado** |
| **Consistencia** | Variable | **Determinista** |
| **Controles ISO** | Puede inventar | **Oficiales verificados** |
| **Métricas** | Confusas | **Claras** |
| **Velocidad** | 10-30 seg | **<1 seg** |
| **Debugging** | Imposible | **Fácil (logs)** |

---

## 📦 STACK TECNOLÓGICO

- **Runtime:** Node.js 20+
- **Lenguaje:** TypeScript
- **Framework:** Express.js
- **Deployment:** Docker (Coolify)
- **Dependencias:** Mínimas (express, cors, helmet)

---

## 🏗️ ARQUITECTURA

```
Action1 (PowerShell v5.4.9)
    ↓ JSON + TXT
OneDrive
    ↓
N8N Workflow
    ├─ Excel (Dashboard, Hallazgos, Análisis IA)
    │
    └─ HTTP Request → hardening-analyzer:3000
           ├─ POST /analyze-individual
           ├─ POST /analyze-global
           └─ Controles ISO hardcodeados
               ↓
           HTML + JSON
               ↓
    Email con reporte
```

---

## 📁 ESTRUCTURA DEL PROYECTO

```
hardening-analyzer/
├── src/
│   ├── server.ts              # Servidor Express principal
│   ├── routes/
│   │   └── analyze.ts         # Endpoints /analyze-*
│   ├── iso27001/
│   │   └── controles.ts       # Mapeo ISO 27001:2022 oficial
│   ├── generators/
│   │   └── html.ts            # Generador de HTML
│   └── utils/
│       └── types.ts           # Tipos TypeScript
│
├── Dockerfile                 # Para Coolify deployment
├── package.json
├── tsconfig.json
├── DEPLOYMENT.md              # Guía de deployment
└── README.md                  # Este archivo
```

---

## 🔌 API ENDPOINTS

### GET /health
Health check del servicio

**Response:**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "uptime": 12345,
  "timestamp": "2026-03-09T..."
}
```

### POST /analyze-individual
Analiza un equipo crítico individual

**Request:**
```json
{
  "hostname": "PT307",
  "compliance_score": 84,
  "errors": 0,
  "warnings": 4,
  "checks": { ... }
}
```

**Response:**
```json
{
  "hostname": "PT307",
  "fecha_analisis": "2026-03-09T...",
  "score": 84,
  "resumen_ejecutivo": "El equipo PT307 presenta...",
  "controles_iso_afectados": [
    {
      "id": "A.9.2",
      "nombre": "Gestión de acceso de usuarios",
      "descripcion": "...",
      "anexo": "A.9"
    }
  ],
  "riesgos_principales": [...],
  "acciones_recomendadas": [...],
  "metricas_cumplimiento": {...}
}
```

### POST /analyze-global
Genera reporte HTML consolidado de múltiples equipos

**Request:**
```json
{
  "equipos": [
    { "hostname": "PT307", "compliance_score": 84, ... },
    { "hostname": "PT298", "compliance_score": 91, ... }
  ],
  "fecha_analisis": "2026-03-09T..."
}
```

**Response:**
```json
{
  "html": "<!DOCTYPE html>...",
  "metricas": {
    "total_equipos": 2,
    "equipos_ok": 1,
    "equipos_warning": 1,
    "equipos_criticos": 0,
    "score_promedio": 87.5
  }
}
```

---

## 🚀 INSTALACIÓN Y DEPLOYMENT

### Opción 1: Coolify (Recomendado)

Ver **[DEPLOYMENT.md](./DEPLOYMENT.md)** para guía completa paso a paso.

### Opción 2: Docker manual

```bash
# Build
docker build -t hardening-analyzer .

# Run
docker run -d \
  --name hardening-analyzer \
  -p 3000:3000 \
  -e NODE_ENV=production \
  hardening-analyzer
```

### Opción 3: Node.js directo

```bash
# Instalar dependencias
npm install

# Compilar TypeScript
npm run build

# Iniciar en producción
npm start

# O desarrollo con hot-reload
npm run dev
```

---

## 🧪 TESTING

### Test local

```bash
# Iniciar servidor
npm run dev

# En otra terminal:
curl http://localhost:3000/health

curl -X POST http://localhost:3000/analyze-individual \
  -H "Content-Type: application/json" \
  -d @test-data/PT307.json
```

### Test con N8N

1. Deploy en Coolify
2. Modificar workflow N8N (ver DEPLOYMENT.md)
3. Lanzar Action1 en 1 equipo
4. Verificar email recibido

---

## 📊 CONTROLES ISO 27001 IMPLEMENTADOS

Mapeo verificado contra **ISO 27001:2022 Anexo A**:

- **A.5.1** - Políticas de seguridad de la información
- **A.8.3** - Manipulación de soportes (BitLocker)
- **A.8.9** - Gestión de la configuración
- **A.8.23** - Filtrado web
- **A.9.2** - Gestión de acceso de usuarios (LAPS, admins)
- **A.9.4** - Gestión de información de autenticación
- **A.12.4** - Registro y supervisión (Wazuh)
- **A.12.5** - Control del software en explotación (Antivirus)
- **A.12.6** - Gestión de vulnerabilidad técnica (Parches)
- **A.13.1** - Gestión de seguridad de redes (Firewall)
- **A.13.2** - Transferencia de información (SMBv1)

**Total:** 11 controles oficiales verificados

---

## 🔧 CONFIGURACIÓN

### Variables de entorno

```bash
# .env (opcional)
NODE_ENV=production
PORT=3000
```

### Coolify

```yaml
Environment Variables:
  NODE_ENV: production
  PORT: 3000

Resources:
  Memory: 512M
  CPU: 0.5

Network:
  Type: Internal
  Port: 3000
```

---

## 📝 LOGS

### Formato de logs

```
[2026-03-09T10:30:45.123Z] POST /analyze-individual - 200 (145ms)
[ANÁLISIS INDIVIDUAL] PT307 - Score: 84%
[ANÁLISIS GLOBAL] 30 equipos - Score promedio: 82.5%
```

### Ver logs en Coolify

```
Coolify → hardening-analyzer → Logs → Live Logs
```

---

## 🆘 TROUBLESHOOTING

Ver sección completa en **[DEPLOYMENT.md](./DEPLOYMENT.md)**

**Problemas comunes:**
- ❌ No conecta → Verificar red Docker en Coolify
- ❌ 500 error → Ver logs, verificar JSON
- ❌ Timeout → Aumentar timeout en N8N

---

## 📈 ROADMAP

### v1.0 (Actual) ✅
- [x] Análisis individual
- [x] Reporte global HTML
- [x] Controles ISO 27001 oficiales
- [x] Deployment Coolify

### v1.1 (Futuro)
- [ ] Análisis histórico (tendencias)
- [ ] Más controles ISO (A.14, A.15...)
- [ ] Exportar PDF además de HTML
- [ ] Dashboard interactivo (React)

---

## 📜 LICENCIA

UNLICENSED - Uso interno Sisteplant IT

---

## 👤 AUTOR

**Sisteplant IT**  
Proyecto: Auditoría Hardening ISO 27001

---

## 🙏 AGRADECIMIENTOS

- ISO 27001:2022 por los controles oficiales
- N8N por la plataforma de automatización
- Coolify por el deployment simplificado

---

**¿Preguntas?** Ver [DEPLOYMENT.md](./DEPLOYMENT.md) o revisar logs de Coolify/N8N
