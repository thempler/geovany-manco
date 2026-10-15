# Dashboard local para OWASP ZAP

Interfaz local en PowerShell para lanzar análisis con OWASP ZAP Baseline, consultar alertas y mantener un historial de informes en el equipo.

## Requisitos

- Windows con PowerShell 5.1 o posterior.
- Docker Desktop iniciado y con acceso a la imagen de OWASP ZAP.
- Solo objetivos propios o para los que tengas autorización expresa.

## Inicio rápido

Abre PowerShell en esta carpeta y ejecuta:

```powershell
.\start-zap-dashboard.ps1
```

Visita `http://127.0.0.1:8787/`. El perfil predeterminado solo permite `localhost`, `127.0.0.1` y `host.docker.internal`, útiles para laboratorios locales.

Para habilitar un objetivo autorizado, añade su hostname explícitamente al iniciar el servicio:

```powershell
.\start-zap-dashboard.ps1 -AllowedHosts localhost,127.0.0.1,host.docker.internal,mi-sitio.example
```

La coincidencia del hostname es exacta. Puedes cambiar el puerto con `-Port 8788`. Deja abierta la consola de PowerShell mientras usas el dashboard; pulsa `Ctrl+C` para detenerlo.

## Alcance

Los perfiles combinan ZAP Baseline, rastreo tradicional y Client Spider con tiempos limitados, y análisis pasivo. No habilitan análisis activo ni envían cargas de explotación. No sustituyen una prueba de penetración completa; los flujos autenticados, las validaciones manuales y los hallazgos requieren revisión adicional.

Confirma el alcance y la autorización antes de cada análisis. Un resultado de una herramienta automatizada debe validarse en contexto antes de tratarse como vulnerabilidad confirmada.

## Informes y privacidad

Los informes e historial se guardan localmente en `zap-report.json` y `scan-runs/`. Pueden contener hosts, rutas y evidencias del objetivo; no los compartas ni los agregues al repositorio. El archivo `.gitignore` de esta carpeta los excluye.