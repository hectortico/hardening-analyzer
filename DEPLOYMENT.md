# 🚀 DEPLOYMENT EN COOLIFY - GUÍA PASO A PASO

## 📋 PRE-REQUISITOS

- ✅ Acceso a tu panel de Coolify: `https://hosting.ticosys.com`
- ✅ N8N ya corriendo en Coolify
- ✅ Este proyecto en un repositorio Git (GitHub/GitLab) o como ZIP

---

## 🐳 OPCIÓN 1: DEPLOYMENT DESDE GITHUB (Recomendado)

### Paso 1: Subir código a GitHub

```bash
# En tu máquina local, dentro de la carpeta hardening-analyzer:
git init
git add .
git commit -m "Initial commit: Hardening Analyzer v1.0"

# Crear repo en GitHub y conectarlo:
git remote add origin https://github.com/TU-USUARIO/hardening-analyzer.git
git branch -M main
git push -u origin main
```

### Paso 2: Crear recurso en Coolify

1. Abrir Coolify: `https://hosting.ticosys.com`
2. Click en **"+ New Resource"**
3. Seleccionar **"Public Repository"**

### Paso 3: Configurar aplicación

```yaml
Repository Configuration:
  Repository URL: https://github.com/TU-USUARIO/hardening-analyzer
  Branch: main
  
Build Settings:
  Build Pack: nixpacks (auto-detect)
  OR si falla, usar "Dockerfile"
  
  Build Command: npm install && npm run build
  Start Command: npm start
  
Network:
  Port: 3000
  Type: Internal (NO exponer a internet)
  Service Name: hardening-analyzer
  
Environment Variables:
  NODE_ENV: production
  PORT: 3000

Resources (opcional):
  Memory Limit: 512M
  CPU Limit: 0.5
```

### Paso 4: Deploy

1. Click **"Deploy"**
2. Esperar build (2-3 minutos)
3. Verificar logs: debe decir "Servidor corriendo en puerto 3000"

---

## 🐳 OPCIÓN 2: DEPLOYMENT DESDE ZIP

### Paso 1: Preparar ZIP

```bash
# Comprimir todo el proyecto:
zip -r hardening-analyzer.zip hardening-analyzer/ \
  -x "hardening-analyzer/node_modules/*" \
  -x "hardening-analyzer/dist/*" \
  -x "hardening-analyzer/.git/*"
```

### Paso 2: En Coolify

1. **"+ New Resource"** → **"Docker Image"** o **"Simple Dockerfile"**
2. Subir ZIP
3. Misma configuración que Opción 1

---

## ✅ VERIFICAR QUE FUNCIONA

### Test 1: Health Check

```bash
# Desde terminal con acceso a red interna de Coolify:
curl http://hardening-analyzer:3000/health

# Respuesta esperada:
{
  "status": "ok",
  "version": "1.0.0",
  "uptime": 123,
  "timestamp": "2026-03-09T..."
}
```

### Test 2: Endpoint de análisis

```bash
curl -X POST http://hardening-analyzer:3000/analyze-individual \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "TEST",
    "compliance_score": 85,
    "errors": 0,
    "warnings": 2,
    "checks": {}
  }'

# Debe retornar JSON con análisis
```

---

## 🔧 CONFIGURAR N8N PARA USAR CODE

### Nodo 1: Reemplazar "ANALISTA IA INDIVIDUAL"

1. Abrir workflow en N8N: `🔒 Auditoría Hardening ISO 27001 - v5 FINAL`
2. **BORRAR** nodo `🤖 ANALISTA IA INDIVIDUAL` (Gemini)
3. **CREAR** nuevo nodo:

```yaml
Tipo: HTTP Request
Nombre: 📡 Code - Análisis Individual

Method: POST
URL: http://hardening-analyzer:3000/analyze-individual

Headers:
  Content-Type: application/json

Body:
  Content Type: JSON
  Body: {{ $json }}

Options:
  Timeout: 30000 (30 segundos)
```

4. **Conectar** igual que estaba Gemini:
   - Input: desde `🔀 Expandir Críticos`
   - Output: hacia `📊 Extraer Análisis IA`

### Nodo 2: Reemplazar "Analista Global"

1. **BORRAR** nodo `Analista Global` (Gemini)
2. **CREAR** nuevo nodo:

```yaml
Tipo: HTTP Request
Nombre: 📡 Code - Análisis Global

Method: POST
URL: http://hardening-analyzer:3000/analyze-global

Headers:
  Content-Type: application/json

Body:
  Content Type: JSON
  Body: {{ $json }}

Options:
  Timeout: 60000 (60 segundos)
```

3. **Conectar** igual que estaba:
   - Input: desde `📦 Agregar Análisis`
   - Output: hacia `Formatear HTML`

### Guardar Workflow

1. Click **"Save"** en N8N
2. **Activar** workflow si estaba desactivado

---

## 🧪 TESTING END-TO-END

### Test Completo

1. Lanzar script PowerShell desde Action1 en **1 equipo de prueba**
2. Esperar que suba JSON a OneDrive
3. N8N detecta archivo nuevo
4. Verificar en logs de Coolify:
   ```
   [ANÁLISIS INDIVIDUAL] PT307 - Score: 84%
   ```
5. Verificar email recibido con HTML correcto
6. Verificar Excel actualizado

### Si hay errores

**Ver logs en Coolify:**
1. Coolify → hardening-analyzer → Logs
2. Buscar líneas con `[ERROR]`

**Logs de N8N:**
1. N8N → Executions
2. Ver detalles del nodo que falló

---

## 🔄 UPDATES Y MANTENIMIENTO

### Actualizar código (con GitHub)

```bash
# Hacer cambios en código
git add .
git commit -m "Mejoras en análisis"
git push origin main

# Coolify detecta push automáticamente y redeploya
# O hacerlo manual: Coolify → hardening-analyzer → Redeploy
```

### Ver logs en tiempo real

```bash
# En Coolify:
Coolify → hardening-analyzer → Logs → Live Logs
```

### Reiniciar servicio

```bash
# En Coolify:
Coolify → hardening-analyzer → Restart
```

---

## 🆘 TROUBLESHOOTING

### Error: "Cannot connect to hardening-analyzer:3000"

**Causa:** N8N no puede alcanzar el servicio

**Solución:**
1. Verificar que ambos (N8N y hardening-analyzer) están en la **misma red Docker de Coolify**
2. En Coolify → hardening-analyzer → Network → debe estar en misma red que N8N
3. Usar nombre del servicio: `hardening-analyzer:3000` (NO `localhost`)

### Error: "500 Internal Server Error"

**Causa:** Error en el código de análisis

**Solución:**
1. Ver logs en Coolify
2. Verificar que el JSON enviado desde N8N es válido
3. Revisar campo `hostname` y `compliance_score` existen

### Error: "timeout"

**Causa:** El análisis tarda más de 30/60 segundos

**Solución:**
1. Aumentar timeout en nodo HTTP Request de N8N
2. Optimizar código si procesa muchos equipos

---

## 📊 MÉTRICAS Y MONITOREO

### Dashboard de Coolify

- **CPU Usage:** Debe estar <50%
- **Memory:** Debe estar <300MB
- **Response Time:** <1 segundo típico

### Logs importantes

Buscar estas líneas en logs:
```
✅ Servidor corriendo en puerto 3000
[ANÁLISIS INDIVIDUAL] PT307 - Score: 84%
[ANÁLISIS GLOBAL] 30 equipos - Score promedio: 82.5%
```

---

## 🎯 SIGUIENTE PASO

Una vez deployado y funcionando:

1. **Test con 1 equipo** ✅
2. **Test con 5 equipos** ✅
3. **Test con 30 equipos** (donde Gemini falla) ✅
4. **Desactivar nodos Gemini antiguos** en N8N
5. **Celebrar** 🎉 (ahora es gratis y sin límites)

---

## 💡 TIPS

- **Auto-deploy:** Conectar GitHub con Coolify para deploy automático en cada push
- **Backups:** Coolify hace backups automáticos de la configuración
- **Rollback:** Si algo falla, puedes volver a versión anterior desde Coolify
- **Logs:** Configurar retención de logs en Coolify (recomendado: 7 días)

---

**¿Necesitas ayuda?** Revisa los logs de Coolify y N8N, ahí está toda la info de debugging.
