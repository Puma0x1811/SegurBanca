import secrets
import string
import sys

# Manejo flexible de importaciones para ejecución directa o desde paquete
try:
    from backend.anti_pattern_filter import FiltroAntiPatron
    from backend.rule_templates import PlantillasDeReglas
except ModuleNotFoundError:
    from anti_pattern_filter import FiltroAntiPatron
    from rule_templates import PlantillasDeReglas


class GeneradorClaves:
    """
    Motor criptográfico para la generación de claves y PINs.
    Combina las restricciones de sintaxis de 'rule_templates' con
    el filtrado Anti-PII y Anti-Patrón de 'anti_pattern_filter'.
    """

    @staticmethod
    def _tiene_consecutivos_iguales(cadena: str, max_permitidos: int) -> bool:
        """Verifica si existen más de 'max_permitidos' caracteres iguales seguidos."""
        if max_permitidos is None or max_permitidos <= 0:
            return False
        contador = 1
        for i in range(1, len(cadena)):
            if cadena[i] == cadena[i - 1]:
                contador += 1
                if contador > max_permitidos:
                    return True
            else:
                contador = 1
        return False

    @classmethod
    def generar(
        cls, 
        clave_plantilla: str, 
        filtro: FiltroAntiPatron, 
        longitud_deseada: int = None, 
        nombre_banco_custom: str = ""
    ) -> str:
        """
        Genera una clave o PIN seguro que cumple con la regla seleccionada
        y aprueba todos los filtros Anti-PII del usuario.
        """
        regla = PlantillasDeReglas.obtener_regla(clave_plantilla)
        
        # Determinar longitud dentro de los rangos permitidos por la regla
        long_min = regla.get("longitud_min", 8)
        long_max = regla.get("longitud_max", 16)
        
        if longitud_deseada is None:
            longitud = long_min
        else:
            longitud = max(long_min, min(longitud_deseada, long_max))

        # Determinar palabras prohibidas para la entidad bancaria
        palabras_banco = list(regla.get("palabras_prohibidas", []))
        if nombre_banco_custom.strip():
            palabras_banco.append(nombre_banco_custom.strip().lower())

        max_intentos = 2000
        for _ in range(max_intentos):
            candidato = cls._construir_candidato(regla, longitud)
            
            # 1. Validar restricción de caracteres consecutivos repetidos
            max_iguales = regla.get("max_consecutivos_iguales")
            if max_iguales and cls._tiene_consecutivos_iguales(candidato, max_iguales):
                continue

            # 2. Validar con el filtro Anti-PII y Anti-Patrón
            if filtro.es_clave_segura(candidato, palabras_banco=palabras_banco):
                return candidato

        raise ValueError("No se pudo generar una clave segura con los parámetros especificados.")

    @classmethod
    def _construir_candidato(cls, regla: dict, longitud: int) -> str:
        """Construye un string aleatorio respetando la sintaxis y tipos de caracteres."""
        tipo = regla.get("tipo", "NUMERICO")
        
        if tipo == "NUMERICO":
            return "".join([secrets.choice(string.digits) for _ in range(longitud)])

        # Configurar pools de caracteres según la regla específica
        pool_mayus = string.ascii_uppercase if regla.get("requiere_mayuscula") or regla.get("requiere_letras") else ""
        pool_minus = string.ascii_lowercase if regla.get("requiere_minuscula") or regla.get("requiere_letras") else ""
        pool_nums = string.digits if regla.get("requiere_numero") or regla.get("requiere_letras") else ""
        
        # Símbolos especiales (usar whitelist específica si la plantilla la define)
        if "caracteres_especiales_permitidos" in regla:
            pool_especial = "".join(regla["caracteres_especiales_permitidos"])
        elif regla.get("requiere_especial"):
            pool_especial = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        else:
            pool_especial = ""

        # Pool completo de caracteres válidos
        pool_completo = pool_mayus + pool_minus + pool_nums + pool_especial
        if not pool_completo:
            pool_completo = string.ascii_letters + string.digits

        # Garantizar al menos un carácter de cada conjunto requerido
        caracteres_obligatorios = []
        if pool_mayus:
            caracteres_obligatorios.append(secrets.choice(pool_mayus))
        if pool_minus:
            caracteres_obligatorios.append(secrets.choice(pool_minus))
        if pool_nums:
            caracteres_obligatorios.append(secrets.choice(pool_nums))
        if pool_especial:
            caracteres_obligatorios.append(secrets.choice(pool_especial))

        # Completar la longitud restante aleatoriamente
        restante = longitud - len(caracteres_obligatorios)
        resto_caracteres = [secrets.choice(pool_completo) for _ in range(max(0, restante))]
        
        # Mezclar para evitar que los obligatorios queden siempre en las primeras posiciones
        combinado = caracteres_obligatorios + resto_caracteres
        secrets.SystemRandom().shuffle(combinado)
        
        return "".join(combinado)


# --- BLOQUE DE PRUEBA Y VERIFICACIÓN INTEGRADA ---
if __name__ == "__main__":
    if sys.stdout.encoding != 'utf-8':
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except AttributeError:
            pass

    print("=== PROBANDO EL GENERADOR INTEGRADO DE CLAVES ===\n")

    # Perfil de prueba del usuario (simulando datos PII)
    perfil_usuario = FiltroAntiPatron(
        cedula="12345678",
        telefono="04141234567",
        fecha_nac="15081985",
        primer_nombre="Jaime",
        primer_apellido="Perez",
        pasaporte="112233"
    )

    bancos_prueba = [
        ("bdv_clave_web", 12, ""),
        ("bbva_clave_web", 12, ""),
        ("mercantil_clave_web", 10, ""),
        ("banca_general", 14, "Banesco"),
        ("sim_card", 4, "")
    ]

    for id_plantilla, lon, banco_custom in bancos_prueba:
        clave_gen = GeneradorClaves.generar(
            clave_plantilla=id_plantilla,
            filtro=perfil_usuario,
            longitud_deseada=lon,
            nombre_banco_custom=banco_custom
        )
        print(f"[OK] [PLANTILLA]: {id_plantilla}")
        print(f"     |-- Clave Generada: {clave_gen}")
        print(f"     +-- Longitud final: {len(clave_gen)} caracteres\n")