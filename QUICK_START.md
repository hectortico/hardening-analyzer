# ⚡ QUICK START - Hardening Analyzer

**Tiempo estimado:** 30 minutos  
**Nivel:** Intermedio

---

## 🎯 OBJETIVO

Deployar Hardening Analyzer en Coolify y conectarlo con N8N para reemplazar Gemini.

---

## ✅ CHECKLIST PRE-DEPLOYMENT

- [ ] Acceso a Coolify: `https://hosting.ticosys.com`
- [ ] N8N corriendo en Coolify
- [ ] Cuenta de GitHub (para subir código)
- [ ] Terminal con Git instalado

---

## 🚀 PASOS RÁPIDOS

### 1. Subir código a GitHub (5 min)

```bash
# Desde la carpeta hardening-analyzer:
git init
git add .
git commit -m "Initial commit"

# Crear repo en GitHub y conectar:
git remote add origin https://github.com/TU-USUARIO/hardening-analyzer.git
git branch -M main
git push -u origin main
```

### 2. Deploy en Coolify (10 min)

1. **Coolify** → `+ New Resource`
2. **Public Repository**
3. Configurar:
   ```
   URL: https://github.com/TU-USUARIO/hardening-analyzer
   Branch: main
   Build: npm install && npm run build
   Start: npm start
   Port: 3000
   Network: Internal
   ```
4. **Deploy**
5. Esperar 2-3 minutos

### 3. Verificar que funciona (2 min)

En Coolify, ver logs:
```
✅ Servidor corriendo en puerto 3000
```

### 4. Modificar N8N (10 min)

**Workflow:** `🔒 Auditoría Hardening ISO 27001 - v5 FINAL`

#### A. Reemplazar nodo individual

1. **BORRAR:** `🤖 ANALISTA IA INDIVIDUAL`
2. **CREAR:** HTTP Request
   ```
   URL: http://hardening-analyzer:3000/analyze-individual
   Method: POST
   Body: {{ $json }}
   ```
3. **Conectar:** Input desde `🔀 Expandir Críticos`

#### B. Reemplazar nodo global

1. **BORRAR:** `Analista Global`
2. **CREAR:** HTTP Request
   ```
   URL: http://hardening-analyzer:3000/analyze-global
   Method: POST
   Body: {{ $json }}
   ```
3. **Conectar:** Input desde `📦 Agregar Análisis`

4. **GUARDAR** workflow

### 5. Probar (5 min)

1. Lanzar Action1 en 1 equipo
2. Esperar procesamiento
3. Verificar email recibido
4. ✅ Listo!

---

## 🎉 ÉXITO

Si recibiste el email con el reporte HTML:
- ✅ Code está funcionando
- ✅ Gemini reemplazado
- ✅ $0/mes en costes
- ✅ Sin límite de equipos

---

## 🆘 SI ALGO FALLA

### Error: "Cannot connect"
```
Solución: 
Coolify → hardening-analyzer → Network
Verificar que está en misma red que N8N
```

### Error: "500 Internal Server Error"
```
Solución:
Coolify → hardening-analyzer → Logs
Buscar línea con [ERROR]
```

### Email no llega
```
Solución:
N8N → Executions → Ver último workflow
Identificar qué nodo falló
```

---

## 📚 MÁS INFO

- **Deployment completo:** Ver [DEPLOYMENT.md](./DEPLOYMENT.md)
- **Documentación:** Ver [README.md](./README.md)
- **Logs:** Coolify → hardening-analyzer → Logs

---

**¡Ahora a deployar!** 🚀
