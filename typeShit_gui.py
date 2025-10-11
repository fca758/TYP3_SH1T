from __future__ import annotations

import io
import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional



# Importar algoritmos, si no funcioan entonces da un error
from typeShit import encriptacionArchivo, desencriptarArchivo, generadorDeClave


# Lista de algoritmos soportados
algoritmos = ["AES-128", "AES-192", "AES-256"]


# Clase principal de la aplicación
class App(tk.Tk):
    WINDOW_W = 640
    WINDOW_H = 420    


    # Inicialización de la ventana
    def __init__(self) -> None:
        super().__init__()
        self.title("TYP3_SH1T GUI")
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
        algo_combo = ttk.Combobox(parent, textvariable=self.algorithm_var, values=algoritmos, state="readonly", width=12, style='Custom.TCombobox')
        algo_combo.grid(column=1, row=1, sticky=tk.W)

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
        gen_btn = tk.Button(parent, text="Generar", command=lambda: self.on_generar_clave(self.algorithm_var.get()), bg=button_bg, fg=button_fg)
        gen_btn.grid(column=3, row=3, sticky=tk.W)

        # Botón de ejecutar
        run_btn = tk.Button(parent, text="Ejecutar", command=self.run_action, bg=button_bg, fg=button_fg)
        run_btn.grid(column=1, row=4, pady=(8, 8), sticky=tk.W)


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

        if not infile:
            messagebox.showwarning("Falta archivo", "Debes seleccionar un archivo de entrada.")
            return

        # Capturar stdout de las funciones llamadas para mostrar en la GUI
        buf = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = buf
            if action == "encrypt":


                #ENCRIPTACIÓN DEL ARCHIVO
                encriptacionArchivo(infile, None, key, algorithm=algo)
            else:


                #DESENCRIPTACIÓN DEL ARCHIVO
                desencriptarArchivo(infile, None, key, algorithm=algo)
        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error al ejecutar la acción: {e}")
        finally:
            sys.stdout = old_stdout

        output = buf.getvalue()
        self.output_txt.delete("1.0", tk.END)
        self.output_txt.insert(tk.END, output)

    def on_generar_clave(self, algorithm: Optional[str] = None) -> None:

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

        if key_val is None:
            # Error al generar clave - fallback a clave aleatoria
            try:
                sizes = {"AES-128": 16, "AES-192": 24, "AES-256": 32}
                n = sizes.get(algorithm, 16)
                key_bytes = os.urandom(n)
                key_hex = key_bytes.hex()
                self.output_txt.insert(tk.END, f"[Keygen fallback] Generated {n} bytes\n")
            except Exception:
                pass


        else:
            # Colocar la clave generada en el campo de texto y en la salida
            try:
                self.key_var.set(key_hex)
            except Exception:
                pass
            try:
                self.output_txt.insert(tk.END, f"Generated key ({algorithm}): {key_hex}\n")
            except Exception:
                pass

if __name__ == "__main__":
    app = App()
    app.mainloop()
