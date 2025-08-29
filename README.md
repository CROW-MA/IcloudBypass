# iOS Forensic Tool

Una herramienta avanzada de análisis forense para dispositivos iOS que permite análisis de dispositivos, backups, jailbreak, bypass de iCloud y descifrado de backups cifrados.

## 🚨 Advertencia Legal

**IMPORTANTE**: Esta herramienta está diseñada únicamente para:
- Investigación forense legal autorizada
- Recuperación de dispositivos de propiedad legítima
- Propósitos educativos y de investigación

El uso de esta herramienta para acceder a dispositivos sin autorización explícita es ilegal y constituye una violación de leyes de privacidad y propiedad.

## ✨ Características

- **Análisis Forense Completo**: Dispositivos conectados y backups de iTunes
- **Múltiples Métodos de Jailbreak**: Soporte para checkra1n, unc0ver, palera1n y Odyssey
- **Bypass de iCloud**: 6 métodos diferentes para bypass de activación
- **Descifrado de Backups**: Ataque por diccionario y fuerza bruta
- **Extracción de Datos**: Contactos, mensajes, registros de llamadas, etc.
- **Interfaz de Consola**: Fácil de usar con menús interactivos

## 📋 Requisitos del Sistema

### Sistema Operativo
- macOS (recomendado)
- Linux (con libimobiledevice instalado)
- Windows (con configuración adicional)

### Dependencias de Python
```bash
pip install cryptography beautifulsoup4 requests biplist

Herramientas Externas

    libimobiledevice (para macOS/Linux)

    iTunes (para backups en Windows)

🛠 Instalación

    Clonar el repositorio:

bash

git clone https://github.com/CROWN-MA/ios-forensic-tool.git
cd ios-forensic-tool

    Instalar dependencias:

bash

pip install -r requirements.txt

    Instalar libimobiledevice (macOS):

bash

brew install libimobiledevice

🚀 Uso Básico
Ejecutar la herramienta:
bash

python ios_forensic_tool.py

Menú Principal:
text

=== HERRAMIENTA AVANZADA DE FORENSIC iOS ===
1. Análisis forense de dispositivo
2. Análisis forense de backup  
3. Realizar jailbreak
4. Eliminar cuenta iCloud (bypass)
5. Descifrar backup cifrado
6. Extraer datos específicos
7. Configurar herramientas
8. Salir

Ejemplos de Uso:

    Analizar dispositivo conectado:

        Seleccionar opción 1 → Análisis básico

        El sistema detectará automáticamente el dispositivo

    Analizar backup de iTunes:

        Seleccionar opción 2

        Ingresar ruta del backup (ej: ~/Library/Application Support/MobileSync/Backup/)

    Realizar jailbreak:

        Seleccionar opción 3

        Elegir método (checkra1n, unc0ver, etc.)

        Seguir instrucciones en pantalla

🔧 Métodos de Bypass iCloud

La herramienta incluye 6 métodos diferentes:

    GSX: Solicitud oficial a Apple (requiere documentación)

    Jailbreak + DNS: Redirección de tráfico de activación

    Checkm8: Exploit hardware para dispositivos A5-A11

    MDM: Uso de perfiles empresariales

    Modificación PLIST: Edición de archivos del sistema

    Proxy Server: Interceptación de tráfico de red

📊 Estructura del Proyecto
text

ios-forensic-tool/
├── ios_forensic_tool.py  # Script principal
├── requirements.txt      # Dependencias de Python
├── ios_forensic_tool.log # Logs de ejecución
└── README.md            # Este archivo

🔍 Análisis Forense
Datos Extraíbles:

    Información del dispositivo

    Contactos y agenda

    Mensajes SMS/MMS

    Registros de llamadas

    Historial de Safari

    Datos de ubicación

    Información de redes WiFi

    Datos de aplicaciones

Formatos de Salida:

    JSON estructurado

    Logs detallados

    Reportes legibles

⚠️ Limitaciones

    Algunas funciones requieren jailbreak

    El bypass de iCloud puede ser temporal

    La efectividad varía según la versión de iOS

    Algunos métodos requieren hardware específico

🤝 Contribución

Las contribuciones son bienvenidas. Por favor:

    Fork el proyecto

    Crea una rama para tu feature (git checkout -b feature/AmazingFeature)

    Commit tus cambios (git commit -m 'Add AmazingFeature')

    Push a la rama (git push origin feature/AmazingFeature)

    Abre un Pull Request

📝 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo LICENSE para más detalles.
🆘 Soporte

Si encuentras problemas:

    Revisa los logs en ios_forensic_tool.log

    Verifica que todas las dependencias estén instaladas

    Asegúrate de tener los permisos adecuados

    Abre un issue en GitHub con detalles del error

🔄 Actualizaciones

    v1.0: Versión inicial con funciones básicas

    v1.1: Mejora en métodos de bypass

    v1.2: Optimización de análisis forense

Nota: Esta herramienta se actualiza constantemente para adaptarse a los cambios en los sistemas iOS. Siempre usa la versión más reciente.
