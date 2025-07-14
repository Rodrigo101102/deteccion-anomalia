# Manual de Usuario - Sistema de Detección de Anomalías

## Introducción

El Sistema de Detección de Anomalías es una plataforma web que automatiza la captura, procesamiento y análisis del tráfico de red para identificar actividades sospechosas o maliciosas.

## Acceso al Sistema

### URL de Acceso
Acceda al sistema a través de su navegador web en: `http://su-servidor.com`

### Credenciales de Acceso
El sistema requiere autenticación. Contacte al administrador para obtener sus credenciales:
- **Usuario estándar**: Acceso de solo lectura a datos de tráfico
- **Administrador**: Acceso completo al sistema y configuración

## Interfaz Principal

### Página de Inicio
La página principal presenta:
- Resumen de las funcionalidades del sistema
- Enlaces de acceso rápido
- Información sobre el estado del sistema

### Barra de Navegación
- **Dashboard**: Panel principal con estadísticas
- **Tráfico**: Lista de tráfico de red capturado
- **Predicciones**: Estado del procesamiento ML
- **Análisis** (Solo Admin): Análisis detallado
- **Estado Sistema** (Solo Admin): Monitoreo del sistema

## Funcionalidades por Rol

### Usuario Estándar

#### 1. Visualización de Tráfico de Red
**Ubicación**: Menú → Tráfico

**Características**:
- Lista paginada de registros de tráfico (20 por página)
- Filtros por protocolo, estado y fecha
- Información detallada de cada flujo de red

**Campos Mostrados**:
- **IP Origen/Destino**: Direcciones y puertos involucrados
- **Protocolo**: TCP, UDP, ICMP, HTTP, etc.
- **Tamaño**: Bytes transferidos
- **Duración**: Tiempo del flujo
- **Estado**: Normal, Anómalo, Pendiente
- **Fecha**: Momento de captura

#### 2. Filtros Disponibles
- **Por Protocolo**: Filtre por tipo de protocolo de red
- **Por Estado**: Normal, Anómalo, Pendiente
- **Por Fecha**: Seleccione un día específico

#### 3. Paginación
- Navegue entre páginas usando los controles inferiores
- 20 registros por página para optimizar rendimiento

### Administrador

#### 1. Dashboard Principal
**Ubicación**: Menú → Dashboard

**Información Mostrada**:
- **Tarjetas de Estadísticas**:
  - Tráfico Normal (verde)
  - Tráfico Anómalo (rojo)
  - Tráfico Pendiente (amarillo)
  - Total de Registros (azul)

- **Gráficos Interactivos**:
  - Estadísticas por protocolo (barras)
  - Distribución de tráfico (dona)

- **Tabla de Anomalías Recientes**:
  - Últimas 10 anomalías detectadas
  - Información detallada de cada incidente

#### 2. Análisis Detallado
**Ubicación**: Menú → Análisis

**Funciones**:
- Análisis temporal (últimos 7 días)
- Top IPs con mayor tráfico anómalo
- Tendencias y patrones
- Métricas de rendimiento del sistema

#### 3. Estado del Sistema
**Ubicación**: Menú → Estado Sistema

**Monitoreo**:
- Estado de sesiones de captura
- Usuarios del sistema
- Rendimiento de componentes
- Logs de actividad

#### 4. Control de Capturas
**Función**: Iniciar/Detener capturas de tráfico
**Ubicación**: Botones en vista de Tráfico

**Operaciones**:
- **Iniciar Captura**: Comienza nueva sesión de captura
- **Detener Captura**: Finaliza captura activa
- **Estado en Tiempo Real**: Monitoreo de capturas activas

## Uso del Sistema

### 1. Flujo Típico de Trabajo

#### Para Usuarios
1. **Iniciar Sesión**: Acceder con credenciales
2. **Ver Dashboard**: Revisar estado general
3. **Explorar Tráfico**: Usar filtros para encontrar información específica
4. **Analizar Resultados**: Revisar anomalías detectadas

#### Para Administradores
1. **Iniciar Sesión**: Acceder con credenciales de admin
2. **Verificar Estado**: Revisar dashboard y estado del sistema
3. **Iniciar Captura**: Si es necesario, iniciar nueva captura
4. **Monitorear Procesamiento**: Verificar que el pipeline funcione
5. **Analizar Resultados**: Revisar anomalías y tendencias
6. **Tomar Acciones**: Investigar anomalías detectadas

### 2. Interpretación de Resultados

#### Estados de Tráfico
- **🟢 NORMAL**: Tráfico típico y esperado
- **🔴 ANÓMALO**: Tráfico sospechoso que requiere investigación
- **🟡 PENDIENTE**: Tráfico capturado pero aún no analizado

#### Indicadores de Anomalía
El sistema considera anómalo el tráfico con:
- Tamaños de paquete inusualmente grandes
- Duraciones de conexión prolongadas
- Patrones de comunicación atípicos
- Puertos o protocolos inesperados

#### Puntuación de Confianza
- **0.8-1.0**: Alta confianza en la predicción
- **0.6-0.8**: Confianza media
- **0.0-0.6**: Baja confianza (revisar manualmente)

### 3. Filtros y Búsquedas

#### Filtro por Protocolo
- **TCP**: Tráfico web, email, transferencias
- **UDP**: DNS, video streaming, gaming
- **ICMP**: Ping, diagnósticos de red
- **HTTP/HTTPS**: Tráfico web específico

#### Filtro por Fecha
- Seleccione una fecha específica para análisis temporal
- Útil para investigar incidentes específicos

#### Combinación de Filtros
- Combine múltiples filtros para búsquedas precisas
- Ejemplo: TCP + Anómalo + Fecha específica

## Características Avanzadas

### 1. Auto-actualización
- El dashboard se actualiza automáticamente cada 30 segundos
- Los gráficos reflejan cambios en tiempo real
- Las alertas aparecen automáticamente

### 2. Exportación de Datos
- Use el botón "Exportar" para descargar datos
- Formatos disponibles: CSV, Excel
- Útil para análisis externos

### 3. Responsive Design
- La interfaz se adapta a dispositivos móviles
- Acceso completo desde tablets y smartphones
- Navegación optimizada para pantallas pequeñas

## Seguridad y Mejores Prácticas

### 1. Gestión de Credenciales
- Use contraseñas fuertes y únicas
- Cambie contraseñas regularmente
- No comparta credenciales de acceso

### 2. Interpretación de Anomalías
- **No todas las anomalías son maliciosas**
- Verifique contexto antes de tomar acciones
- Correlacione con otros sistemas de seguridad
- Documente investigaciones y resultados

### 3. Monitoreo Continuo
- Revise dashboard regularmente
- Configure alertas para anomalías críticas
- Mantenga logs de actividades importantes

## Solución de Problemas

### 1. Problemas de Acceso
**Síntoma**: No puede iniciar sesión
**Solución**:
- Verifique credenciales
- Contacte al administrador
- Limpie caché del navegador

### 2. Datos No Aparecen
**Síntoma**: No se muestran datos de tráfico
**Solución**:
- Verifique que hay capturas activas
- Espere al procesamiento (puede tomar minutos)
- Revise filtros aplicados

### 3. Página No Carga
**Síntoma**: Errores de carga
**Solución**:
- Actualice la página (F5)
- Verifique conexión a internet
- Contacte soporte técnico

### 4. Gráficos No Se Muestran
**Síntoma**: Gráficos en blanco
**Solución**:
- Habilite JavaScript en el navegador
- Desactive bloqueadores de contenido
- Use navegador compatible (Chrome, Firefox, Safari)

## Soporte Técnico

### Contacto
- **Email**: soporte@empresa.com
- **Teléfono**: +1 (555) 123-4567
- **Horario**: Lunes a Viernes, 8:00 AM - 6:00 PM

### Información para Soporte
Cuando contacte soporte, proporcione:
- Nombre de usuario
- Descripción del problema
- Pasos para reproducir el error
- Captura de pantalla (si aplica)
- Navegador y versión utilizada

### Recursos Adicionales
- **Documentación técnica**: `/docs/`
- **Videos tutoriales**: Portal interno
- **FAQ**: Preguntas frecuentes
- **Foro de usuarios**: Comunidad interna

## Actualizaciones del Sistema

### Notificaciones
- Las actualizaciones se anuncian por email
- Cambios importantes se muestran en la interfaz
- Revise notas de versión regularmente

### Nuevas Funcionalidades
- El sistema se actualiza regularmente
- Nuevas características se documentan
- Training disponible para funciones nuevas

### Mantenimiento Programado
- Notificación previa de mantenimientos
- Ventanas de mantenimiento típicamente nocturnas
- Servicios críticos se mantienen disponibles

## Glosario

**Anomalía**: Comportamiento de red que se desvía de patrones normales
**Flujo**: Secuencia de paquetes entre dos puntos de red
**PCAP**: Formato de archivo para datos de red capturados
**Pipeline**: Secuencia automatizada de procesamiento de datos
**Protocolo**: Reglas de comunicación de red (TCP, UDP, etc.)
**Sesión**: Período de captura continua de tráfico de red