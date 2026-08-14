import os
import sys
import customtkinter as ctk

# Función para resolver rutas locales y dentro del .exe
def obtener_ruta_recurso(ruta_relativa):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, ruta_relativa)

# Incluir raíz del proyecto en sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from backend.anti_pattern_filter import FiltroAntiPatron
from backend.rule_templates import PlantillasDeReglas
from backend.password_generator import GeneradorClaves

# Asegurar que Python encuentre los módulos de la carpeta 'backend' al ejecutar directamente
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from backend.anti_pattern_filter import FiltroAntiPatron
from backend.rule_templates import PlantillasDeReglas
from backend.password_generator import GeneradorClaves

# Configuración visual de la aplicación
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class SegurBancaApp(ctk.CTk):
    """
    Interfaz Gráfica Principal para el Generador Criptográfico SegurBanca.
    Diseñada para la banca venezolana y hardening de dispositivos móviles.
    """
    def __init__(self):
        super().__init__()

        # Configuración de la Ventana Principal
        self.title("SegurBanca - Generador de Claves Ciberseguras")
        self.geometry("620x780")
        self.resizable(False, False)
       
       # Carga del icono de la aplicación
        ruta_icono = obtener_ruta_recurso(os.path.join("assets", "icon.ico"))
        if os.path.exists(ruta_icono):
            self.iconbitmap(ruta_icono)

        # Mapeo de Plantillas (Nombre legible -> Clave técnica)
        self.lista_plantillas_raw = PlantillasDeReglas.listar_plantillas()
        self.opciones_menu = [nombre for _, nombre in self.lista_plantillas_raw]
        self.mapa_nombres = {nombre: clave for clave, nombre in self.lista_plantillas_raw}

        self._crear_interfaz()
        self._actualizar_regla_seleccionada(self.opciones_menu[0])

    def _crear_interfaz(self):
        """Construye las secciones y widgets de la aplicación."""
        
        # --- ENCABEZADO ---
        self.frame_header = ctk.CTkFrame(self, fg_color="transparent")
        self.frame_header.pack(fill="x", padx=20, pady=(15, 5))

        self.lbl_titulo = ctk.CTkLabel(
            self.frame_header, 
            text="SegurBanca", 
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.lbl_titulo.pack(anchor="w")

        self.lbl_subtitulo = ctk.CTkLabel(
            self.frame_header, 
            text="Generador por Capas para Banca Venezolana y Seguridad Móvil",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.lbl_subtitulo.pack(anchor="w")

        # --- SECCIÓN 1: FILTRO ANTI-PII (DATOS PERSONALES) ---
        self.frame_pii = ctk.CTkFrame(self)
        self.frame_pii.pack(fill="x", padx=20, pady=10)

        self.lbl_sec1 = ctk.CTkLabel(
            self.frame_pii, 
            text="1. Perfil de Usuario (Filtro Anti-Patrón PII)", 
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.lbl_sec1.grid(row=0, column=0, columnspan=2, padx=15, pady=(10, 5), sticky="w")

        # Filas de Inputs PII
        self.txt_nombre = self._crear_campo_input(self.frame_pii, "Primer Nombre:", 1, 0)
        self.txt_apellido = self._crear_campo_input(self.frame_pii, "Primer Apellido:", 1, 1)
        
        self.txt_cedula = self._crear_campo_input(self.frame_pii, "Cédula de Identidad:", 2, 0)
        self.txt_telefono = self._crear_campo_input(self.frame_pii, "Teléfono Móvil:", 2, 1)

        self.txt_fecha = self._crear_campo_input(self.frame_pii, "Fecha Nac. (DDMMAAAA):", 3, 0)
        self.txt_pasaporte = self._crear_campo_input(self.frame_pii, "Pasaporte (Opcional):", 3, 1)

        # --- SECCIÓN 2: SELECCIÓN DE BANCO / SERVICIO ---
        self.frame_servicio = ctk.CTkFrame(self)
        self.frame_servicio.pack(fill="x", padx=20, pady=10)

        self.lbl_sec2 = ctk.CTkLabel(
            self.frame_servicio, 
            text="2. Seleccionar Plataforma / Servicio", 
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.lbl_sec2.pack(anchor="w", padx=15, pady=(10, 5))

        self.cbo_servicio = ctk.CTkOptionMenu(
            self.frame_servicio,
            values=self.opciones_menu,
            command=self._actualizar_regla_seleccionada,
            width=540
        )
        self.cbo_servicio.pack(padx=15, pady=5)

        # Campo dinámico para escribir el nombre de un banco personalizado
        self.frame_banco_custom = ctk.CTkFrame(self.frame_servicio, fg_color="transparent")
        self.lbl_custom = ctk.CTkLabel(self.frame_banco_custom, text="Nombre del Banco (ej: Banesco, Plaza):")
        self.lbl_custom.pack(side="left", padx=(0, 10))
        self.txt_banco_custom = ctk.CTkEntry(self.frame_banco_custom, width=280)
        self.txt_banco_custom.pack(side="right")

        # --- SECCIÓN 3: CONTROL DE LONGITUD DINÁMICA ---
        self.frame_longitud = ctk.CTkFrame(self)
        self.frame_longitud.pack(fill="x", padx=20, pady=10)

        self.lbl_sec3 = ctk.CTkLabel(
            self.frame_longitud, 
            text="3. Longitud de la Clave", 
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.lbl_sec3.pack(anchor="w", padx=15, pady=(10, 5))

        self.frame_slider_row = ctk.CTkFrame(self.frame_longitud, fg_color="transparent")
        self.frame_slider_row.pack(fill="x", padx=15, pady=5)

        self.slider_longitud = ctk.CTkSlider(
            self.frame_slider_row,
            from_=8,
            to=16,
            number_of_steps=8,
            command=self._on_slider_change
        )
        self.slider_longitud.pack(side="left", fill="x", expand=True, padx=(0, 15))

        self.lbl_valor_longitud = ctk.CTkLabel(
            self.frame_slider_row, 
            text="8 Caracteres", 
            font=ctk.CTkFont(size=13, weight="bold")
        )
        self.lbl_valor_longitud.pack(side="right")

        self.lbl_descripcion_regla = ctk.CTkLabel(
            self.frame_longitud,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="gray",
            wraplength=540,
            justify="left"
        )
        self.lbl_descripcion_regla.pack(anchor="w", padx=15, pady=(0, 10))

        # --- SECCIÓN 4: BOTÓN Y RESULTADO ---
        self.btn_generar = ctk.CTkButton(
            self, 
            text="GENERAR CLAVE SEGURA", 
            font=ctk.CTkFont(size=15, weight="bold"),
            height=45,
            command=self._generar_clave
        )
        self.btn_generar.pack(fill="x", padx=20, pady=10)

        self.frame_resultado = ctk.CTkFrame(self)
        self.frame_resultado.pack(fill="x", padx=20, pady=5)

        self.txt_resultado = ctk.CTkEntry(
            self.frame_resultado, 
            font=ctk.CTkFont(size=18, family="Consolas", weight="bold"),
            justify="center",
            height=40
        )
        self.txt_resultado.pack(side="left", fill="x", expand=True, padx=(10, 10), pady=10)

        self.btn_copiar = ctk.CTkButton(
            self.frame_resultado, 
            text="Copiar", 
            width=90,
            height=40,
            command=self._copiar_al_portapapeles
        )
        self.btn_copiar.pack(side="right", padx=(0, 10), pady=10)

        self.lbl_estado = ctk.CTkLabel(self, text="", font=ctk.CTkFont(size=12))
        self.lbl_estado.pack(pady=5)

    def _crear_campo_input(self, parent, label_text, row, col):
        """Método auxiliar para crear etiquetas y campos de entrada en cuadrícula."""
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid(row=row, column=col, padx=10, pady=5, sticky="ew")
        
        lbl = ctk.CTkLabel(frame, text=label_text, font=ctk.CTkFont(size=12))
        lbl.pack(anchor="w")
        
        entry = ctk.CTkEntry(frame, width=250)
        entry.pack(anchor="w", fill="x", expand=True)
        return entry

    def _actualizar_regla_seleccionada(self, nombre_legible):
        """Ajusta dinámicamente los límites del slider y visibilidad de campos según el banco."""
        clave_regla = self.mapa_nombres[nombre_legible]
        regla = PlantillasDeReglas.obtener_regla(clave_regla)

        min_l = regla.get("longitud_min", 8)
        max_l = regla.get("longitud_max", 16)

        # Ajustar el slider de longitud
        self.slider_longitud.configure(
            from_=min_l,
            to=max_l,
            number_of_steps=max(1, max_l - min_l)
        )
        
        val_defecto = min_l if min_l == max_l else min(12, max_l)
        self.slider_longitud.set(val_defecto)
        self._on_slider_change(val_defecto)

        # Mostrar u ocultar campo de Banco Personalizado
        if regla.get("permite_nombre_banco_personalizado"):
            self.frame_banco_custom.pack(fill="x", padx=15, pady=5)
        else:
            self.frame_banco_custom.pack_forget()

        # Actualizar descripción técnica de la regla
        self.lbl_descripcion_regla.configure(text=f"Regla: {regla.get('descripcion', '')}")

    def _on_slider_change(self, value):
        """Actualiza la etiqueta con el valor actual del slider."""
        self.lbl_valor_longitud.configure(text=f"{int(value)} Caracteres")

    def _generar_clave(self):
        """Recolecta datos del perfil y genera la clave usando el backend."""
        try:
            self.lbl_estado.configure(text="", text_color="white")

            # 1. Instanciar filtro Anti-PII con los datos ingresados
            filtro = FiltroAntiPatron(
                cedula=self.txt_cedula.get(),
                telefono=self.txt_telefono.get(),
                fecha_nac=self.txt_fecha.get(),
                primer_nombre=self.txt_nombre.get(),
                primer_apellido=self.txt_apellido.get(),
                pasaporte=self.txt_pasaporte.get()
            )

            # 2. Identificar regla seleccionada
            nombre_legible = self.cbo_servicio.get()
            clave_regla = self.mapa_nombres[nombre_legible]
            longitud = int(self.slider_longitud.get())
            banco_custom = self.txt_banco_custom.get() if self.frame_banco_custom.winfo_viewable() else ""

            # 3. Generar clave criptográfica
            clave = GeneradorClaves.generar(
                clave_plantilla=clave_regla,
                filtro=filtro,
                longitud_deseada=longitud,
                nombre_banco_custom=banco_custom
            )

            # 4. Mostrar resultado
            self.txt_resultado.delete(0, "end")
            self.txt_resultado.insert(0, clave)
            self.lbl_estado.configure(text="✔ Clave generada exitosamente y verificada contra el filtro PII.", text_color="#2ECC71")

        except Exception as e:
            self.lbl_estado.configure(text=f"❌ Error: {str(e)}", text_color="#E74C3C")

    def _copiar_al_portapapeles(self):
        """Copia la clave generada al portapapeles del sistema."""
        clave = self.txt_resultado.get()
        if clave:
            self.clipboard_clear()
            self.clipboard_append(clave)
            self.lbl_estado.configure(text="📋 Clave copiada al portapapeles.", text_color="#3498DB")


# --- PUNTO DE ENTRADA PARA EJECUCIÓN DIRECTA (F6 en Notepad++) ---
if __name__ == "__main__":
    app = SegurBancaApp()
    app.mainloop()