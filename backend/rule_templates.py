class PlantillasDeReglas:
    """
    Catálogo de reglas de sintaxis y restricciones técnicas para capas 
    de seguridad del celular y plataformas de la banca nacional en Venezuela.
    """
    
    REGLAS = {
        # --- CAPAS DE PROTECCIÓN DEL DISPOSITIVO MÓVIL ---
        "pantalla_celular": {
            "nombre": "PIN de Bloqueo de Pantalla (Sustituto de Patrón)",
            "tipo": "NUMERICO",
            "longitud_min": 4,
            "longitud_max": 8,
            "descripcion": "Acceso principal al teléfono. Permite seleccionar PIN numérico de 4, 6 u 8 dígitos."
        },
        "sim_card": {
            "nombre": "PIN de Tarjeta SIM (Digitel / Movistar / Movilnet)",
            "tipo": "NUMERICO",
            "longitud_min": 4,
            "longitud_max": 4,
            "descripcion": "Protege tu línea contra secuestro de SMS. PIN numérico estricto de 4 dígitos."
        },
        "cifrado_microsd": {
            "nombre": "PIN / Clave de Cifrado MicroSD",
            "tipo": "ALFANUMERICO",
            "longitud_min": 6,
            "longitud_max": 16,
            "descripcion": "Evita la extracción de fotos y documentos. Permite contraseñas o PINs extensos."
        },

        # --- BANCA NACIONAL ESTRUCTURADA ---
        "bdv_clave_web": {
            "nombre": "Banco de Venezuela (BDV) - Clave BDVenlínea / App",
            "tipo": "COMPLEJO",
            "longitud_min": 8,
            "longitud_max": 15,
            "requiere_mayuscula": True,
            "requiere_minuscula": True,
            "requiere_numero": True,
            "requiere_especial": True,
            "max_consecutivos_iguales": 2,
            "palabras_prohibidas": ["bdv", "banco", "venezuela"],
            "descripcion": "Exige mayúscula, minúscula, número, especial. Prohíbe 3 caracteres iguales seguidos."
        },
        "bdv_pago_movil": {
            "nombre": "Banco de Venezuela (BDV) - PIN Pago Móvil / Cajero",
            "tipo": "NUMERICO",
            "longitud_min": 4,
            "longitud_max": 4,
            "descripcion": "PIN numérico de 4 dígitos para BDVApp y operaciones en cajero."
        },
        "bbva_clave_web": {
            "nombre": "BBVA Provincial - Clave Provinet / App",
            "tipo": "COMPLEJO",
            "longitud_min": 8,
            "longitud_max": 16,
            "requiere_letras": True,
            "requiere_numero": True,
            "caracteres_especiales_permitidos": ["-", "/", "=", ".", "$", "#", "*"],
            "palabras_prohibidas": ["bbva", "provin"],
            "descripcion": "Exige letras y números. Whitelist estricta de símbolos: -, /, =, ., $, #, *"
        },
        "mercantil_clave_web": {
            "nombre": "Mercantil - Clave Mercantil en Línea / App",
            "tipo": "COMPLEJO",
            "longitud_min": 8,
            "longitud_max": 15,
            "requiere_mayuscula": True,
            "requiere_minuscula": True,
            "requiere_especial": True,
            "caracteres_especiales_permitidos": ["=", "*", "-", ".", "_"],
            "max_consecutivos_iguales": 2,
            "palabras_prohibidas": ["mercantil", "mercan"],
            "descripcion": "Sin espacios. Whitelist de símbolos: =, *, -, ., _. Máximo 2 repetidos."
        },
        "mercantil_pago_movil": {
            "nombre": "Mercantil - PIN Tpago / Llave Mercantil",
            "tipo": "NUMERICO",
            "longitud_min": 4,
            "longitud_max": 4,
            "descripcion": "PIN de 4 dígitos para Tpago y banca telefónica."
        },

        # --- BANCA GENERAL / PERSONALIZADA ---
        "banca_general": {
            "nombre": "Otro Banco Nacional (Banesco, BNC, Plaza, etc.)",
            "tipo": "COMPLEJO",
            "longitud_min": 8,
            "longitud_max": 16,
            "requiere_mayuscula": True,
            "requiere_minuscula": True,
            "requiere_numero": True,
            "requiere_especial": True,
            "max_consecutivos_numericos": 2,
            "permite_nombre_banco_personalizado": True,
            "descripcion": "Plantilla universal de alta entropía. Permite vetar el nombre del banco ingresado por el usuario."
        }
    }

    @classmethod
    def obtener_regla(cls, clave_plantilla: str) -> dict:
        """Devuelve la configuración completa de una plantilla según su identificador."""
        if clave_plantilla in cls.REGLAS:
            return cls.REGLAS[clave_plantilla]
        raise KeyError(f"La plantilla '{clave_plantilla}' no existe en el catálogo.")

    @classmethod
    def listar_plantillas(cls) -> list:
        """Devuelve la lista completa de servicios y bancos configurados en el catálogo."""
        return [(clave, datos["nombre"]) for clave, datos in cls.REGLAS.items()]