import secrets
import re

class FiltroAntiPatron:
    """
    Motor de filtrado criptográfico de baja entropía y protección Anti-PII.
    Prohíbe la generación de claves derivadas de datos personales del usuario
    (Cédula, Teléfono, Fechas, Pasaporte, Nombre, Apellido, Cuentas)
    así como patrones numéricos débiles y nombres de entidades financieras.
    """
    def __init__(
        self, 
        cedula: str = "", 
        telefono: str = "", 
        fecha_nac: str = "", 
        primer_nombre: str = "", 
        primer_apellido: str = "", 
        pasaporte: str = "", 
        cuenta_bancaria: str = ""
    ):
        self.patrones_prohibidos_num = set()
        self.palabras_prohibidas_texto = set()
        
        # Lista Negra Universal de secuencias numéricas débiles
        self.lista_negra_universal = [
            "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
            "1234", "4321", "2345", "5432", "3456", "6543", "0123", "3210",
            "2580", "0852", "1470", "0741", "3690", "0963", # Patrones geométricos de teclado
            "2022", "2023", "2024", "2025", "2026", "2027"  # Años recientes
        ]
        
        # 1. Extraer fragmentos numéricos (Cédula, Teléfono, Fecha, Pasaporte, Cuenta)
        self._extraer_fragmentos_numericos(cedula, telefono, fecha_nac, pasaporte, cuenta_bancaria)
        
        # 2. Extraer palabras personales (Primer Nombre y Primer Apellido)
        self._extraer_palabras_personales(primer_nombre, primer_apellido)

    def _extraer_fragmentos_numericos(self, *campos_numericos):
        """Limpia los campos numéricos recibidos y extrae subcadenas contiguas de 2 a 4 dígitos."""
        texto_unificado = "".join([str(campo) for campo in campos_numericos if campo])
        solo_numeros = re.sub(r'\D', '', texto_unificado)
        
        for tamano in [2, 3, 4]:
            for i in range(len(solo_numeros) - tamano + 1):
                subcadena = solo_numeros[i:i + tamano]
                self.patrones_prohibidos_num.add(subcadena)

    def _extraer_palabras_personales(self, primer_nombre: str, primer_apellido: str):
        """Almacena el nombre y apellido en minúsculas si tienen al menos 3 letras."""
        nombre_limpio = primer_nombre.strip().lower()
        apellido_limpio = primer_apellido.strip().lower()
        
        if len(nombre_limpio) >= 3:
            self.palabras_prohibidas_texto.add(nombre_limpio)
            
        if len(apellido_limpio) >= 3:
            self.palabras_prohibidas_texto.add(apellido_limpio)

    def es_clave_segura(self, clave_candidata: str, palabras_banco: list = None) -> bool:
        """
        Evalúa si una clave o PIN candidato es seguro.
        Retorna True si aprueba todos los filtros, o False si contiene datos prohibidos.
        """
        if not clave_candidata:
            return False

        clave_lower = clave_candidata.lower()

        # A. Filtro de Lista Negra Universal
        for patron in self.lista_negra_universal:
            if patron in clave_candidata:
                return False

        # B. Filtro Anti-PII Numérico (Cédula, Teléfono, Fecha, Pasaporte)
        for patron_num in self.patrones_prohibidos_num:
            if len(patron_num) >= 2 and patron_num in clave_candidata:
                return False

        # C. Filtro Anti-PII Textual (Primer Nombre y Primer Apellido)
        for palabra in self.palabras_prohibidas_texto:
            if palabra in clave_lower:
                return False

        # D. Filtro de Palabras del Banco / Entidad (ej: 'BDV', 'BBVA', 'Mercantil')
        if palabras_banco:
            for palabra_banco in palabras_banco:
                if palabra_banco.strip() and palabra_banco.strip().lower() in clave_lower:
                    return False

        return True