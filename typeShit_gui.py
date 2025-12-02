from __future__ import annotations

import io
import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional
import secrets


# Importar algoritmos, si no funcioan entonces da un error
from typeShit import encriptacionArchivo, desencriptarArchivo, generadorDeClave, get_stored_keys

# Lista de algoritmos soportados
AES_names = ["AES-128", "AES-192", "AES-256"]
AES_modes = ["CBC", "CFB", "OFB"]


# Clase principal de la aplicación
class App(tk.Tk):
    WINDOW_W = 640
    WINDOW_H = 420    


    # Inicialización de la ventana
    def __init__(self) -> None:
        super().__init__()
        self.title("TYP3_SH1T")
        self.geometry(f"{self.WINDOW_W}x{self.WINDOW_H}")
        self.resizable(False, False)

        self.bg_image = None
        self.pil_img = None
        self.panel_image = None


        script_dir = os.path.dirname(__file__)
        img_path = os.path.join(script_dir, "itslit.png")

        if img_path:
            try:
                from PIL import Image, ImageTk, ImageOps  # type: ignore
                pil = Image.open(img_path).convert("RGBA")
                self.pil_img = pil
                pil_bg = ImageOps.fit(pil, (self.WINDOW_W, self.WINDOW_H), Image.LANCZOS)
                self.bg_image = ImageTk.PhotoImage(pil_bg.convert("RGB"))
            except Exception:
                
                try:
                    self.bg_image = tk.PhotoImage(file=img_path)
                except Exception:
                    self.bg_image = None
        else:
            self.bg_image = None

        self.create_widgets()

    def create_widgets(self) -> None:
        # Poner imagen de fondo si está disponible
        if self.bg_image is not None:
            bg_label = tk.Label(self, image=self.bg_image)
            bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        else:
            notice = tk.Label(self, text="(No se cargó imagen de fondo lit.png/jpg)", bg="#222222", fg="white")
            notice.place(relx=0.5, rely=0.02, anchor=tk.N)


        panel_parent = None
        panel_w, panel_h = 600, 380
        if self.pil_img is not None:
            try:
                from PIL import ImageTk, Image
                W, H = self.pil_img.size
                left = max(0, (W - panel_w) // 2)
                top = max(0, (H - panel_h) // 2)
                panel_crop = self.pil_img.crop((left, top, left + panel_w, top + panel_h))
                overlay = Image.new('RGBA', panel_crop.size, (0, 0, 0, int(255 * 0.18)))
                panel_with_overlay = Image.alpha_composite(panel_crop.convert('RGBA'), overlay)
                self.panel_image = ImageTk.PhotoImage(panel_with_overlay.convert('RGB'))

                # place the background and the cropped panel image
                bg_label = tk.Label(self, image=self.bg_image)
                bg_label.place(x=0, y=0, relwidth=1, relheight=1)
                panel_label = tk.Label(self, image=self.panel_image, bd=0)
                panel_label.place(relx=0.5, rely=0.5, anchor=tk.CENTER, width=panel_w, height=panel_h)
                panel_parent = panel_label
            except Exception:
                panel_parent = None

        # Frame padre
        if panel_parent is None:
            parent = tk.Frame(self, bg="#222222", padx=12, pady=12)
            parent.pack(fill=tk.BOTH, expand=True)
        else:
            parent = panel_parent

        # Scheme de colores
        # - decorative labels: transparent over image (bg=None), dark bg when no image
        # - inputs: light background + dark text over image (legible), dark theme otherwise
        # - output: always black background with white text
        label_bg = None if panel_parent is not None else "#222222"
        label_fg = "#79b670" if panel_parent is None else "#000000"
        entry_bg = "#c39c9c" if panel_parent is not None else "#333333"
        entry_fg = "#000000" if panel_parent is not None else "#ffffff"
        button_bg = "#3a8b8a" if panel_parent is None else None
        button_fg = "#000000"
        output_bg = "#000000"
        output_fg = "#FFFFFF"

        # Widgets
        tk.Label(parent, text="Acción:", bg=label_bg, fg=label_fg).grid(column=0, row=0, sticky=tk.W)
        self.action_var = tk.StringVar(value="encrypt")
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass


        try:
            style.configure('Custom.TCombobox', fieldbackground=entry_bg, background=entry_bg, foreground=entry_fg)
        except Exception:
            pass
        action_combo = ttk.Combobox(parent, textvariable=self.action_var, values=["encrypt", "decrypt"], state="readonly", width=12, style='Custom.TCombobox')
        action_combo.grid(column=1, row=0, sticky=tk.W)



        # Input de seleccion de algoritmo
        tk.Label(parent, text="Algoritmo:", bg=label_bg, fg=label_fg).grid(column=0, row=1, sticky=tk.W)
        self.algorithm_var = tk.StringVar(value="AES-128")
        algo_combo = ttk.Combobox(parent, textvariable=self.algorithm_var, values=AES_names, state="readonly", width=12, style='Custom.TCombobox')
        algo_combo.grid(column=1, row=1, sticky=tk.W)
        
        # Input de modo (dependiendo del algoritmo tendrá diferentes opciones)
        tk.Label(parent, text="Modo:", bg=label_bg, fg=label_fg).grid(column=1, row=1, sticky=tk.E, padx=(200,0))
        self.mode_var = tk.StringVar(value="Selecciona")
        mode_combo = ttk.Combobox(parent, textvariable=self.mode_var, values=AES_modes, state="readonly", width=12, style='Custom.TCombobox')
        mode_combo.grid(column=2, row=1, sticky=tk.E)

        # Input de seleccion de archivo
        tk.Label(parent, text="Archivo entrada:", bg=label_bg, fg=label_fg).grid(column=0, row=2, sticky=tk.W)
        self.input_var = tk.StringVar()
        input_entry = tk.Entry(parent, textvariable=self.input_var, width=50, bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)
        input_entry.grid(column=1, row=2, columnspan=2, sticky=tk.W)
        tk.Button(parent, text="Examinar", command=self.browse_input, bg=button_bg, fg=button_fg).grid(column=3, row=2, sticky=tk.W)

        # Input de clave
        tk.Label(parent, text="Clave:", bg=label_bg, fg=label_fg).grid(column=0, row=3, sticky=tk.W)
        self.key_var = tk.StringVar()
        key_entry = tk.Entry(parent, textvariable=self.key_var, width=50, bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)
        key_entry.grid(column=1, row=3, columnspan=2, sticky=tk.W)

        # Botón para generar clave (a la derecha del campo clave)
        gen_btn = tk.Button(parent, text="Generar", command=lambda: self.generarClave(self.algorithm_var.get()), bg=button_bg, fg=button_fg)
        gen_btn.grid(column=3, row=3, sticky=tk.W)

        # Variable para almacenar el IV asociado (hex)
        self.iv_var = tk.StringVar()

        # Botón de ejecutar
        run_btn = tk.Button(parent, text="Ejecutar", command=self.run_action, bg=button_bg, fg=button_fg)
        run_btn.grid(column=1, row=4, pady=(8, 8), sticky=tk.W)

        key_get = tk.Button(parent, text="Buscar clave guardada", command=self.buscarClaveGuardada, bg=button_bg, fg=button_fg)
        key_get.grid(column=2, row=4, pady=(8, 8), sticky=tk.W)

        # Salida de consola
        tk.Label(parent, text="Salida:", bg=label_bg, fg=label_fg).grid(column=0, row=5, sticky=tk.NW)
        self.output_txt = tk.Text(parent, width=78, height=12, wrap=tk.WORD, bg=output_bg, fg=output_fg, insertbackground=output_fg)
        self.output_txt.grid(column=0, row=6, columnspan=4, sticky=tk.W)

        # Ajuste de padding del grid
        for child in parent.winfo_children():
            try:
                child.grid_configure(padx=6, pady=4)
            except Exception:
                pass

    # Método para pedir el archivo
    def browse_input(self) -> None:
        path = filedialog.askopenfilename(title="Selecciona archivo")
        if path:
            self.input_var.set(path)

    # Método para ejecutar la acción seleccionada
    def run_action(self) -> None:
        action = self.action_var.get()
        algo = self.algorithm_var.get()
        infile = self.input_var.get() or None
        key = self.key_var.get() or None
        mode = self.mode_var.get()

        if not infile:
            messagebox.showwarning("Falta archivo", "Debes seleccionar un archivo de entrada.")
            return
        if mode == "Selecciona":
            messagebox.showwarning("Falta modo", "Debes seleccionar un modo de operación.")
            return
        if not key:
            messagebox.showwarning("Falta clave", "Debes proporcionar una clave.")
            return
        # Validación básica de formato/longitud de la clave (hex) según algoritmo
        expected_hex_len = None
        if algo == "AES-128":
            expected_hex_len = 16 * 2
        elif algo == "AES-192":
            expected_hex_len = 24 * 2
        elif algo == "AES-256":
            expected_hex_len = 32 * 2

        # Si la clave parece hexadecimal, verificar longitud
        key_is_hex = False
        try:
            # strip possible spaces
            kstr = key.strip()
            if all(c in "0123456789abcdefABCDEF" for c in kstr):
                key_is_hex = True
        except Exception:
            key_is_hex = False

        if expected_hex_len and key_is_hex and len(kstr) != expected_hex_len:
            messagebox.showwarning("Clave inválida", f"La clave hexadecimal debe tener {expected_hex_len} caracteres para {algo} (ah tienes {len(kstr)}).")
            return
        
        # Capturar stdout de las funciones llamadas para mostrar en la GUI
        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            if action == "encrypt":
                # ENCRIPTACIÓN DEL ARCHIVO
                try:
                    iv = encriptacionArchivo(input_file=infile, output_file=None, mode=mode, key=key, algorithm=algo)
                    # Guardar IV en la GUI (hex) si se generó
                    if iv:
                        try:
                            self.iv_var.set(iv.hex())
                            print(f"IV generado: {iv.hex()}")
                        except Exception:
                            pass
                except Exception as e:
                    # Mostrar traceback completo en la salida para depuración
                    import traceback
                    traceback.print_exc()
                    raise
            else:
                # DESENCRIPTACIÓN DEL ARCHIVO
                # obtener iv desde la variable (si existe)
                iv_hex = self.iv_var.get() or None
                iv_bytes = None
                if iv_hex:
                    try:
                        iv_bytes = bytes.fromhex(iv_hex)
                    except Exception:
                        iv_bytes = None

                try:
                    desencriptarArchivo(input_file=infile, output_file=None, mode=mode, key=key, iv=iv_bytes, algorithm=algo)
                except Exception:
                    import traceback
                    traceback.print_exc()
                    raise
        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error al ejecutar la acción: {e}")
        finally:
            sys.stdout = old_stdout

        output = buf.getvalue()
        self.output_txt.delete("1.0", tk.END)
        self.output_txt.insert(tk.END, output)

    def generarClave(self, algorithm: Optional[str] = None) -> None:

        if algorithm is None:
            algorithm = self.algorithm_var.get()

        key_hex: Optional[str] = None
        try:
            key_val = generadorDeClave(algorithm)
        except Exception as e:
            # Error al generar clave
            try:
                self.output_txt.insert(tk.END, f"[Keygen error] {e}\n")
            except Exception:
                pass
            key_val = None


        key_hex = key_val.hex() if key_val is not None else None

    
        # Colocar la clave generada en el campo de texto y en la salida
        try:
            self.key_var.set(key_hex)
        except Exception:
            pass
        try:
            self.output_txt.insert(tk.END, f"Generated key ({algorithm}): {key_hex}\n")
        except Exception:
            pass

    def buscarClaveGuardada(self) -> None:
        """Muestra un diálogo con las claves guardadas y permite seleccionar una."""
        try:
            stored_keys = get_stored_keys()
        except Exception as e:
            messagebox.showerror("Error", f"Error al leer claves guardadas: {e}")
            return

        if not stored_keys:
            messagebox.showinfo("Sin claves", "No hay claves guardadas.")
            return

        # Heredar estilos de la ventana principal
        label_bg = None if self.panel_image is not None else "#222222"
        label_fg = "#79b670" if self.panel_image is None else "#000000"
        entry_bg = "#c39c9c" if self.panel_image is not None else "#333333"
        entry_fg = "#000000" if self.panel_image is not None else "#ffffff"
        button_bg = "#3a8b8a" if self.panel_image is None else None
        button_fg = "#000000"

        # Crear diálogo de selección
        dialog = tk.Toplevel(self)
        dialog.title("Claves guardadas")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(bg=label_bg)

        # Lista de claves
        frame = tk.Frame(dialog, bg=label_bg, padx=10, pady=10)
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Headers
        tk.Label(frame, text="Fecha", bg=label_bg, fg=label_fg).grid(row=0, column=0, padx=5)
        tk.Label(frame, text="Algoritmo", bg=label_bg, fg=label_fg).grid(row=0, column=1, padx=5)
        tk.Label(frame, text="Modo", bg=label_bg, fg=label_fg).grid(row=0, column=2, padx=5)
        tk.Label(frame, text="Clave", bg=label_bg, fg=label_fg).grid(row=0, column=3, padx=5)


        # Función para eliminar una clave
        def delete_key(entry):
            # Eliminar la entrada del almacén y refrescar el diálogo
            try:
                from typeShit import get_stored_keys, KEYS_FILE, _encrypt_keys_file, _decrypt_keys_file
                _decrypt_keys_file()
                entries = []
                if KEYS_FILE.exists():
                    import json
                    with open(KEYS_FILE, "r") as f:
                        content = f.read().strip()
                        if content:
                            entries = json.loads(content)
                # Filtrar fuera la entrada a eliminar
                entries = [e for e in entries if not (
                    e.get("key") == entry["key"] and
                    e.get("algorithm") == entry["algorithm"] and
                    e.get("mode") == entry["mode"] and
                    e.get("timestamp") == entry["timestamp"]
                )]
                # Guardar actualizado
                with open(KEYS_FILE, "w") as f:
                    json.dump(entries, f, indent=2)
                _encrypt_keys_file()
                if KEYS_FILE.exists():
                    KEYS_FILE.unlink()
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo eliminar la clave: {e}")
            # Refrescar el diálogo
            dialog.destroy()
            self.buscarClaveGuardada()

        # Función para seleccionar una clave
        def select_key(entry):
            self.algorithm_var.set(entry["algorithm"])
            self.mode_var.set(entry["mode"])
            self.key_var.set(entry["key"])
            # Actualizar IV en la GUI (hex) para usar en desencriptación
            if entry.get("iv"):
                try:
                    self.iv_var.set(entry.get("iv"))
                    try:
                        self.selected_iv = bytes.fromhex(entry.get("iv"))
                    except Exception:
                        self.selected_iv = None
                except Exception:
                    pass
            else:
                self.iv_var.set("")
                self.selected_iv = None
            self.output_txt.delete("1.0", tk.END)
            self.output_txt.insert(tk.END, f"Clave seleccionada:\n")
            self.output_txt.insert(tk.END, f"  Fecha: {entry['timestamp']}\n")
            self.output_txt.insert(tk.END, f"  Algoritmo: {entry['algorithm']}\n")
            self.output_txt.insert(tk.END, f"  Modo: {entry['mode']}\n")
            self.output_txt.insert(tk.END, f"  Clave: {entry['key']}\n")
            if entry.get("iv"):
                self.output_txt.insert(tk.END, f"  IV: {entry['iv']}\n")
            dialog.destroy()

        # Mostrar claves
        for i, entry in enumerate(stored_keys, 1):
            tk.Label(frame, text=entry["timestamp"][:16], bg=label_bg, fg=label_fg).grid(row=i, column=0, padx=5)
            tk.Label(frame, text=entry["algorithm"], bg=label_bg, fg=label_fg).grid(row=i, column=1, padx=5)
            tk.Label(frame, text=entry["mode"], bg=label_bg, fg=label_fg).grid(row=i, column=2, padx=5)
            key_preview = entry["key"][:16] + "..."
            tk.Label(frame, text=key_preview, bg=label_bg, fg=label_fg).grid(row=i, column=3, padx=5)
            tk.Button(frame, text="Seleccionar", command=lambda e=entry: select_key(e), bg=button_bg, fg=button_fg).grid(row=i, column=4, padx=5)
            tk.Button(frame, text="Eliminar", command=lambda e=entry: delete_key(e), bg="#c0392b", fg="white").grid(row=i, column=5, padx=5)

        # Botón de cerrar
        tk.Button(frame, text="Cerrar", command=dialog.destroy, bg=button_bg, fg=button_fg).grid(row=len(stored_keys)+1, column=0, columnspan=5, pady=10)

        # Centrar diálogo
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f"{width}x{height}+{x}+{y}")