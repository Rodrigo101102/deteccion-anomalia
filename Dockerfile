FROM python:3.11-slim

# Variables de entorno
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    tshark \
    wireshark-common \
    tcpdump \
    netcat-traditional \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Instalar Node.js para scripts de conversión
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs

# Crear directorio de trabajo
WORKDIR /app

# Copiar archivos de dependencias
COPY requirements.txt package.json ./

# Instalar dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

# Instalar dependencias Node.js
RUN npm install

# Copiar código fuente
COPY . .

# Crear directorios necesarios
RUN mkdir -p media/captures media/csv_files media/models media/exports \
    logs staticfiles

# Establecer permisos
RUN chmod +x scripts/*.py scripts/*.js

# Crear usuario no-root para seguridad
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app
USER appuser

# Exponer puerto
EXPOSE 8000

# Comando por defecto
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120", "anomalia_detection.wsgi:application"]