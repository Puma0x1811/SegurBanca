# SegurBanca: Fundamentos Criptográficos y Fortalecimiento Digital Frente a las Ciberestafas en la Banca Venezolana

**Autor:** Ing° Santiago Vivas-Zambrano
**Investigador y Desarrollador Independiente
**Fecha:** Agosto, 2026
**Caracas, Venezuela
**Categoría:** Ciberseguridad, Criptografía Aplicada, Desarrollo de Software  
**Repositorio:** [github.com/Puma0x1811/SegurBanca](https://github.com/Puma0x1811/SegurBanca)

---

## Resumen (*Abstract*)

El presente trabajo expone el fundamento teórico, el marco socio-tecnológico y la arquitectura de software detrás de **SegurBanca**, una aplicación ejecutable y autónoma (*zero-trust*, 100% *offline*) orientada a la generación de claves de alta entropía y PINs de seguridad. Se analiza el ecosistema bancario venezolano, caracterizado por la adopción masiva del pago móvil y la persistencia de patrones de autenticación altamente vulnerables basados en datos de Identificación Personal (PII). A través de la integración de un filtro de exclusión Anti-PII, el módulo de entropía de Python (`secrets`) y un modelo dinámico de reglas sintácticas bancarias y móviles, **SegurBanca** proporciona una herramienta práctica para mitigar la vulnerabilidad del usuario frente a ataques de ingeniería social, *shoulder surfing*, fuerza bruta y secuestro de SIM (*SIM Swapping*).

---

## 1. Contexto Tecnológico y Socio-Económico Venezolano

En los últimos años, el sistema financiero venezolano ha experimentado una digitalización acelerada impulsada por la necesidad de agilizar transacciones en tiempo real. La consolidación de la plataforma de **Pago Móvil Interbancario (P2P / P2C)** convirtió al teléfono inteligente en el principal terminal bancario del ciudadano común.

Sin embargo, esta transición digital masiva se ha desarrollado en un entorno caracterizado por:

1. **Alta frecuencia de ataques de ingeniería social:** Métodos como el *phishing*, *vishing* y la suplantación de identidad institucional a través de servicios de mensajería (WhatsApp, Telegram) y redes sociales.
2. **Dependencia estricta de la Cédula de Identidad (PII):** El documento nacional de identidad y el número telefónico actúan como identificadores universales de pago, lo que expone públicamente estos datos de manera constante.
3. **Restricciones de conectividad e infraestructura:** Interrupciones en el servicio de datos móviles que desaconsejan el uso de gestores de contraseñas basados estrictamente en la nube para la autenticación inmediata.

---

## 2. Perfil de Vulnerabilidad del Usuario de la Banca Venezolana

El usuario promedio de la banca en Venezuela enfrenta una sobrecarga cognitiva severa: debe gestionar credenciales para múltiples plataformas bancarias (Banco de Venezuela, BBVA Provincial, Banesco, Mercantil, entre otros), cada una con sus propias políticas de expiración y sintaxis.

Esta presión genera patrones de comportamiento de alto riesgo:

* **Reutilización de PII (Personally Identifiable Information):** Inclusión implícita o explícita de fragmentos de la Cédula de Identidad, años de nacimiento o prefijos telefónicos dentro de las claves bancarias y PINs.
* **Sesgo de predictibilidad:** Elección de secuencias numéricas continuas o repetitivas ($1234$, $1111$, $2024$) para recordarlas con facilidad en puntos de venta o al realizar pagos rápidos.
* **Vulnerabilidad por residuo o miradas de terceros (*Shoulder Surfing*):** Preferencia por el uso de patrones de trazo táctil en la pantalla del teléfono celular en lugar de PINs numéricos complejos de 6 u 8 dígitos.

---

## 3. Fundamentos Criptográficos y Teóricos

### 3.1. Entropía de Shannon y Generación Aleatoria
La seguridad de una clave no radica únicamente en su longitud, sino en la incertidumbre o aleatoriedad de su espacio de búsqueda. La entropía de una contraseña se mide en bits mediante la fórmula:

$$H = L \cdot \log_2(S)$$

Donde:
* $H$ es la entropía total en bits.
* $L$ es la longitud de la clave (número de caracteres o dígitos).
* $S$ es el tamaño del conjunto de caracteres permitidos (*alphabet size*).

A diferencia de los generadores pseudoaleatorios estándar (como el módulo `random` de Python, basado en el algoritmo Mersenne Twister y determinista), **SegurBanca** implementa el módulo `secrets`, el cual accede a las fuentes de entropía del sistema operativo (`/dev/urandom` en Unix o `CryptGenRandom` / `BCryptGenRandom` en Windows) garantizando resistencia criptográfica.

### 3.2. Modelo de Exclusión Anti-PII y Anti-Patrón
Un problema recurrente en los generadores estándar es que, aunque la clave sea aleatoria, puede contener casualmente secuencias coincidentes con la cédula o el teléfono del usuario. 

**SegurBanca** introduce un motor de verificación en tiempo real que ejecuta un filtrado previo y posterior:

$$\text{Clave Válida} = C \iff \forall p \in \text{PII}(u), \quad p \notin C \quad \land \quad \text{PatrónDebil}(C) = \text{Falso}$$

Donde $\text{PII}(u)$ representa el conjunto de fragmentos derivados del documento de identidad, número de teléfono y fechas clave del usuario $u$.

### 3.3. Fortalecimiento Móvil en Tres Capas (*Mobile Hardening*)
Para mitigar el riesgo de pérdida o robo físico del dispositivo móvil, la herramienta aplica una estrategia de defensa en profundidad dividida en 3 vectores numéricos/alfanuméricos:

1. **Capa de Dispositivo (Pantalla):** Sustituto del patrón táctil mediante PINs configurables de **4, 6 u 8 dígitos**, incrementando la complejidad contra ataques de fuerza bruta.
2. **Capa de Red (SIM Card):** PIN numérico estricto de 4 dígitos para proteger la línea telefónica contra ataques de *SIM Swapping* (secuestro de SMS de verificación bancaria).
3. **Capa de Almacenamiento (MicroSD):** Clave alfanumérica de hasta 16 caracteres para el cifrado de volumen de la tarjeta de memoria extraíble.

---

## 4. Arquitectura del Software

El sistema está diseñado bajo el principio de separación de responsabilidades (*Separation of Concerns*) e independencia de plataforma:

SegurBanca/
├── backend/
│   ├── anti_pattern_filter.py  # Algoritmos de validación PII y vetos
│   ├── rule_templates.py       # Matriz de reglas bancarias y móviles
│   └── password_generator.py   # Motor de aleatoriedad CSPRNG
└── gui/
└── app_window.py          # Interfaz reactiva (CustomTkinter)

* **Independencia de la Interfaz:** Las reglas bancarias y móviles son parametrizables. La interfaz gráfica ajusta dinámicamente sus restricciones (deslizadores de longitud, tipos de caracteres) mediante la lectura del diccionario de reglas en backend, sin requerir modificaciones en la capa visual.
* **Autonomía Operativa:** Compilado como un binario único estático mediante `PyInstaller`, garantizando ejecuciones 100% locales sin transferencia de paquetes a través de la red (Zero Data Leakage).

---

## 5. Contribución a la Comunidad e Investigación

Este trabajo aporta un modelo de referencia para desarrolladores e investigadores de ciberseguridad en regiones en desarrollo:

1. **Democratización de la Ciberseguridad:** Pone en manos del ciudadano común una herramienta nivel profesional, portable y sin costo, que elimina la dependencia de gestores en la nube de pago.
2. **Caso de Estudio para Educación Superior:** Sirve como arquitectura base pedagógica para la enseñanza de criptografía aplicada, estructuras de datos limpias y desarrollo guiado por reglas en Python.
3. **Mitigación Activa de la Delincuencia Digital:** Al educar al usuario sobre la diferencia entre patrón táctil y PIN numérico de 8 dígitos, y al impedir la reutilización de la Cédula de Identidad, se reduce directamente la tasa de éxito de los ataques de fuerza bruta e ingeniería social en la banca local.

---

## 6. Conclusión

La seguridad de la información no debe depender de la capacidad económica ni del nivel técnico avanzado del usuario. **SegurBanca** demuestra que es posible combinar principios rigurosos de criptografía (CSPRNG, filtro Anti-PII) con una interfaz de usuario intuitiva y adaptada a las realidades específicas de un ecosistema bancario regional. Este proyecto queda a disposición de la comunidad internacional de código abierto como una base sólida para futuras extensiones en investigación y desarrollo de software seguro.

