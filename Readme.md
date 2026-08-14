# 🛡️ SegurBanca

**SegurBanca** es una aplicación de escritorio ligera, segura y ejecutable 100% offline, diseñada para la generación de contraseñas de alta entropía y PINs de seguridad. Está adaptada a los requerimientos sintácticos de la banca venezolana y al fortalecimiento (*hardening*) de dispositivos móviles.

## 🚀 Características Principales

* **Filtro Anti-PII (Información Personal Identificable):** Bloquea automáticamente la inclusión de cédula, números telefónicos, fechas de nacimiento, nombres y pasaportes dentro de las claves generadas.
* **Catálogo de Reglas Bancarias:** Cumple estrictamente las sintaxis y listas de símbolos permitidos de entidades como BDV, BBVA, Mercantil y Banca General.
* **Seguridad Móvil (3 Capas):** Generación de PINs ajustables (4, 6 u 8 dígitos) para el bloqueo de pantalla, PIN numérico estricto para SIM Card y claves de cifrado para tarjetas MicroSD.
* **Criptografía Robusta:** Basado en el módulo nativo `secrets` de Python para aleatoriedad criptográficamente fuerte.
* **Interfaz Gráfica Moderna:** Desarrollada con `CustomTkinter` en modo oscuro con controles deslizantes dinámicos y copia en un clic.

## 🛠️ Tecnologías Utilizadas

* **Lenguaje:** Python 3.x
* **Interfaz Gráfica:** CustomTkinter
* **Compilación:** PyInstaller

## 📋 Estructura del Proyecto

```text
SegurBanca/
├── assets/
│   └── icon.ico           # Recurso gráfico de la aplicación
├── backend/
│   ├── __init__.py
│   ├── anti_pattern_filter.py  # Filtro Anti-PII y Anti-Patrón
│   ├── rule_templates.py       # Catálogo de reglas bancarias y móviles
│   └── password_generator.py   # Motor criptográfico
├── gui/
│   └── app_window.py      # Interfaz gráfica principal
├── .gitignore
└── README.md

✒️ Autor
Desarrollado por Ing° Jaime Meza - Agosto, 2026.