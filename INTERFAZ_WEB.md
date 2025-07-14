# Interfaz Web del Pipeline de Tráfico

Esta implementación integra el flujo completo de captura, procesamiento y predicción de anomalías de tráfico de red en una interfaz web Django fácil de usar.

## Características Principales

### 🔄 Pipeline Completo Integrado
- **Vista unificada** del estado de todas las etapas del pipeline
- **Monitoreo en tiempo real** del progreso de cada fase
- **Navegación intuitiva** entre las diferentes funcionalidades

### 📡 Gestión de Capturas
- **Inicio de capturas** desde la interfaz web
- **Selección de interfaz** de red disponible
- **Configuración de duración** de captura personalizable
- **Monitoreo del estado** de capturas activas
- **Historial completo** de sesiones de captura

### 📊 Procesamiento de CSV
- **Procesamiento masivo** de todos los archivos CSV pendientes
- **Procesamiento individual** de archivos específicos
- **Monitoreo en tiempo real** del progreso
- **Validación y limpieza** automática de datos
- **Manejo de errores** robusto

### 🧠 Predicciones Machine Learning
- **Ejecución de predicciones** con modelo Isolation Forest
- **Configuración de tamaño de lote** para optimizar rendimiento
- **Entrenamiento de modelos** desde la interfaz
- **Visualización de resultados** con gráficos y estadísticas
- **Detección automática de anomalías**

## Estructura de URLs

```
/traffic/                    # Lista de todo el tráfico
/traffic/pipeline/           # Vista principal del pipeline
/traffic/capture/            # Gestión de capturas
/traffic/processing/         # Procesamiento de CSV
/traffic/prediction/         # Predicciones ML
/traffic/analytics/          # Analíticas y estadísticas
```

## Flujo de Trabajo

### 1. Captura de Tráfico
1. Navegar a **Gestión de Capturas**
2. Seleccionar interfaz de red (eth0, wlan0, etc.)
3. Configurar duración de captura
4. Hacer clic en **Iniciar Captura**
5. Monitorear el progreso en tiempo real

### 2. Procesamiento de Datos
1. Una vez completada la captura, ir a **Procesamiento de CSV**
2. Ver archivos CSV pendientes
3. Elegir entre:
   - **Procesar Todos**: Procesa todos los archivos disponibles
   - **Procesar Individual**: Selecciona un archivo específico
4. El sistema limpia y normaliza los datos automáticamente
5. Los datos se insertan en la base de datos

### 3. Predicciones ML
1. Navegar a **Predicciones ML**
2. Verificar que hay registros sin procesar
3. Configurar tamaño de lote según necesidades
4. Hacer clic en **Ejecutar Predicciones ML**
5. Revisar resultados y estadísticas

## Características Técnicas

### Integración con Scripts Existentes
- **Adaptación sin modificar** los scripts originales
- **Funciones wrapper** que encapsulan la lógica existente
- **Manejo de errores** mejorado para la interfaz web
- **Ejecución asíncrona** para evitar bloqueos

### Interfaz Responsiva
- **Bootstrap 5** para diseño moderno y responsive
- **Font Awesome** para iconografía consistente
- **Chart.js** para visualizaciones interactivas
- **AJAX** para actualizaciones sin recargar página

### Control de Acceso
- **Decoradores de permisos** por rol de usuario
- **Operadores**: Pueden ejecutar capturas y procesamiento
- **Analistas**: Acceso completo a predicciones ML
- **Administradores**: Acceso total al sistema

### Monitoreo y Logging
- **Logging automático** de todas las acciones
- **Auditoría de usuarios** para trazabilidad
- **Estadísticas en tiempo real** del pipeline
- **Alertas automáticas** para errores críticos

## Archivos Principales Agregados

### Templates
- `traffic/pipeline.html` - Vista principal del pipeline
- `traffic/capture_management.html` - Gestión de capturas
- `traffic/csv_processing.html` - Procesamiento de CSV
- `traffic/ml_prediction.html` - Predicciones ML
- `traffic/traffic_list.html` - Lista completa de tráfico

### Python
- `apps/traffic/utils.py` - Funciones wrapper para scripts
- `apps/traffic/forms.py` - Formularios para la interfaz
- `apps/traffic/views.py` - Vistas actualizadas con nueva funcionalidad

### Configuración
- `anomalia_detection/urls.py` - URLs actualizadas
- `apps/traffic/urls.py` - URLs de la app traffic
- `templates/base.html` - Navegación mejorada

## Uso desde la Interfaz Web

### Acceso Principal
1. Navegar a `/traffic/pipeline/` para ver el estado completo
2. Usar los botones de **Acciones Rápidas** para acceso directo
3. El **menú de navegación** contiene todas las opciones disponibles

### Operación Típica
1. **Iniciar Captura** → Esperar finalización
2. **Procesar CSV** → Limpiar y cargar datos
3. **Ejecutar ML** → Obtener predicciones
4. **Ver Resultados** → Analizar anomalías detectadas

### Monitoreo
- Las páginas se **auto-actualizan** para mostrar cambios
- **Barras de progreso** indican el estado de operaciones largas
- **Mensajes de estado** informan sobre el éxito o fallos

## Beneficios de la Implementación

✅ **Sin usar consola**: Todo se puede hacer desde la web
✅ **Integración completa**: Los tres scripts trabajan juntos
✅ **Interfaz intuitiva**: Fácil de usar para cualquier usuario
✅ **Monitoreo visual**: Estado claro de cada etapa
✅ **Escalable**: Fácil de extender con nuevas funcionalidades
✅ **Mantenible**: Código bien estructurado y documentado

La implementación permite que usuarios sin conocimientos técnicos puedan ejecutar todo el pipeline de detección de anomalías desde una interfaz web moderna y fácil de usar.