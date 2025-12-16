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
import certificacion

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
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass

        try:
            style.configure('Custom.TCombobox', fieldbackground=entry_bg, background=entry_bg, foreground=entry_fg)
        except Exception:
            pass

        # PARTE SUPERIOR: Usuario Activo y Gestión de Certificados
        tk.Label(parent, text="Usuario activo:", bg=label_bg, fg=label_fg).grid(column=0, row=0, sticky=tk.W)
        self.user_var = tk.StringVar(value="Seleccionar usuario...")
        self.user_combo = ttk.Combobox(parent, textvariable=self.user_var, state="readonly", width=40, style='Custom.TCombobox')
        self.user_combo.grid(column=1, row=0, columnspan=2, sticky=tk.W)
        
        # Botón para refrescar lista de usuarios
        refresh_users_btn = tk.Button(parent, text="⟳ Refrescar", command=self.refresh_user_list, bg=button_bg, fg=button_fg)
        refresh_users_btn.grid(column=3, row=0, sticky=tk.W, padx=2)
        
        # Frame para opciones del usuario (se mostrará debajo del combobox)
        self.user_options_frame = tk.Frame(parent, bg=label_bg)
        self.user_options_frame.grid(column=1, row=1, columnspan=2, sticky=tk.W, pady=(0, 4))
        
        manage_cert_link = tk.Label(self.user_options_frame, text="⚙ Gestionar certificados", 
                                     bg=label_bg, fg="#0066cc", cursor="hand2")
        manage_cert_link.pack(side=tk.LEFT, padx=4)
        manage_cert_link.bind("<Button-1>", lambda e: self.manage_certificates())
        
        # Acción: Encrypt / Decrypt
        tk.Label(parent, text="Acción:", bg=label_bg, fg=label_fg).grid(column=0, row=2, sticky=tk.W)
        self.action_var = tk.StringVar(value="encrypt")
        action_combo = ttk.Combobox(parent, textvariable=self.action_var, values=["encrypt", "decrypt"], state="readonly", width=12, style='Custom.TCombobox')
        action_combo.grid(column=1, row=2, sticky=tk.W)



        # Input de seleccion de algoritmo
        tk.Label(parent, text="Algoritmo:", bg=label_bg, fg=label_fg).grid(column=0, row=3, sticky=tk.W)
        self.algorithm_var = tk.StringVar(value="AES-128")
        algo_combo = ttk.Combobox(parent, textvariable=self.algorithm_var, values=AES_names, state="readonly", width=12, style='Custom.TCombobox')
        algo_combo.grid(column=1, row=3, sticky=tk.W)
        
        # Input de modo (dependiendo del algoritmo tendrá diferentes opciones)
        tk.Label(parent, text="Modo:", bg=label_bg, fg=label_fg).grid(column=1, row=3, sticky=tk.E, padx=(200,0))
        self.mode_var = tk.StringVar(value="Selecciona")
        mode_combo = ttk.Combobox(parent, textvariable=self.mode_var, values=AES_modes, state="readonly", width=12, style='Custom.TCombobox')
        mode_combo.grid(column=2, row=3, sticky=tk.E)

        # Input de seleccion de archivo
        tk.Label(parent, text="Archivo entrada:", bg=label_bg, fg=label_fg).grid(column=0, row=4, sticky=tk.W)
        self.input_var = tk.StringVar()
        input_entry = tk.Entry(parent, textvariable=self.input_var, width=50, bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)
        input_entry.grid(column=1, row=4, columnspan=2, sticky=tk.W)
        tk.Button(parent, text="Examinar", command=self.browse_input, bg=button_bg, fg=button_fg).grid(column=3, row=4, sticky=tk.W)

        # Input de clave
        tk.Label(parent, text="Clave:", bg=label_bg, fg=label_fg).grid(column=0, row=5, sticky=tk.W)
        self.key_var = tk.StringVar()
        key_entry = tk.Entry(parent, textvariable=self.key_var, width=50, bg=entry_bg, fg=entry_fg, insertbackground=entry_fg)
        key_entry.grid(column=1, row=5, columnspan=2, sticky=tk.W)

        # Botón para generar clave (a la derecha del campo clave)
        gen_btn = tk.Button(parent, text="Generar", command=lambda: self.generarClave(self.algorithm_var.get()), bg=button_bg, fg=button_fg)
        gen_btn.grid(column=3, row=5, sticky=tk.W)

        # Variable para almacenar el IV asociado (hex)
        self.iv_var = tk.StringVar()
        # Lista de destinatarios seleccionados para cifrado híbrido
        self.recipients = []

        # Botón de ejecutar
        run_btn = tk.Button(parent, text="Ejecutar", command=self.run_action, bg=button_bg, fg=button_fg)
        run_btn.grid(column=1, row=6, pady=(8, 8), sticky=tk.W)

        key_get = tk.Button(parent, text="Buscar clave guardada", command=self.buscarClaveGuardada, bg=button_bg, fg=button_fg)
        key_get.grid(column=2, row=6, pady=(8, 8), sticky=tk.W)

        multi_enc_btn = tk.Button(parent, text="Cifrado múltiple", command=self.select_recipients, bg="#27ae60", fg="white")
        multi_enc_btn.grid(column=0, row=6, pady=(8,8), sticky=tk.W)

        # Salida de consola
        tk.Label(parent, text="Salida:", bg=label_bg, fg=label_fg).grid(column=0, row=7, sticky=tk.NW)
        self.output_txt = tk.Text(parent, width=78, height=12, wrap=tk.WORD, bg=output_bg, fg=output_fg, insertbackground=output_fg)
        self.output_txt.grid(column=0, row=8, columnspan=4, sticky=tk.W)

        # Ajuste de padding del grid
        for child in parent.winfo_children():
            try:
                child.grid_configure(padx=6, pady=4)
            except Exception:
                pass

        # Inicializar lista de usuarios
        self.after(100, self.refresh_user_list)

    # Método para pedir el archivo
    def browse_input(self) -> None:
        path = filedialog.askopenfilename(title="Selecciona archivo")
        if path:
            self.input_var.set(path)

    def refresh_user_list(self) -> None:
        """Recarga la lista de usuarios disponibles en el combobox."""
        try:
            certs = certificacion.list_certificates()
            user_list = [c.get('identity') for c in certs if c.get('valid')]
            self.user_combo['values'] = user_list
            if not user_list:
                self.user_var.set("Seleccionar usuario...")
            else:
                # Mantener la selección anterior si existe, sino seleccionar la primera
                current = self.user_var.get()
                if current in user_list:
                    self.user_var.set(current)
                else:
                    self.user_var.set(user_list[0])
        except Exception as e:
            messagebox.showerror("Error", f"Error al refrescar usuarios: {e}")
            self.user_combo['values'] = []
            self.user_var.set("Seleccionar usuario...")

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
                # Validar usuario activo y pedir contraseña ANTES de encriptar
                active_user = self.user_var.get()
                password = None
                
                if active_user != "Seleccionar usuario...":
                    from tkinter import simpledialog
                    password = simpledialog.askstring("Autenticación", 
                        f"Contraseña de {active_user} para cifrar y guardar clave:", 
                        show='*', 
                        parent=self)
                    
                    if not password:
                        print("⚠ Operación cancelada por el usuario")
                        return

                    # Validar contraseña intentando descifrar la clave privada
                    try:
                        certificacion._decrypt_user_private_key(active_user, password)
                    except Exception as e:
                        messagebox.showerror("Error de Autenticación", f"Contraseña incorrecta para {active_user}.\nNo se iniciará el cifrado.")
                        return

                # ENCRIPTACIÓN DEL ARCHIVO
                try:
                    # Si hay destinatarios seleccionados, usar cifrado híbrido
                    if hasattr(self, 'recipients') and self.recipients:
                        try:
                            out = certificacion.encrypt_for_recipients(input_file=infile, recipients=self.recipients, algorithm=algo, mode=mode, output_file=None)
                            print(f"Archivo cifrado híbrido para {len(self.recipients)} destinatarios → {out}")
                        except Exception:
                            import traceback
                            traceback.print_exc()
                            raise
                    else:
                        iv = encriptacionArchivo(input_file=infile, output_file=None, mode=mode, key=key, algorithm=algo)
                        # Guardar IV en la GUI (hex) si se generó
                        if iv:
                            try:
                                self.iv_var.set(iv.hex())
                                print(f"IV generado: {iv.hex()}")
                                
                                # Guardar clave automáticamente usando la contraseña validada
                                if active_user != "Seleccionar usuario..." and password:
                                    try:
                                        import user_keys
                                        from pathlib import Path
                                        import re
                                        
                                        # Normalizar clave a bytes
                                        key_bytes = key
                                        if isinstance(key, str):
                                            if re.fullmatch(r"[0-9a-fA-F]+", key) and len(key) % 2 == 0:
                                                try:
                                                    key_bytes = bytes.fromhex(key)
                                                except Exception:
                                                    key_bytes = key.encode("utf-8")
                                            else:
                                                key_bytes = key.encode("utf-8")
                                        
                                        filename = Path(infile).name
                                        user_keys.store_user_key(
                                            active_user, password, 
                                            key_bytes, iv, algo, mode, filename
                                        )
                                        print(f"✓ Clave guardada automáticamente en el almacén de {active_user}")
                                    except Exception as e:
                                        print(f"⚠ Error guardando clave: {e}")
                                        import traceback
                                        traceback.print_exc()
                            except Exception:
                                pass
                except Exception as e:
                    # Mostrar traceback completo en la salida para depuración
                    import traceback
                    traceback.print_exc()
                    raise
            else:
                # DESENCRIPTACIÓN DEL ARCHIVO
                # Si el fichero es híbrido (.hybenc) usar flujo de certificados
                try:
                    if infile.lower().endswith('.hybenc'):
                        try:
                            from tkinter import simpledialog
                            
                            # Usar usuario activo del combobox
                            ident = self.user_var.get()
                            if ident == "Seleccionar usuario...":
                                messagebox.showerror("Error", "Debes seleccionar un usuario activo primero")
                                raise ValueError("No hay usuario activo seleccionado")
                            
                            # Solo pedir contraseña
                            pw = simpledialog.askstring("Contraseña", 
                                f"Contraseña para descifrar como {ident}:", 
                                show='*', 
                                parent=self)
                            if pw is None:
                                raise ValueError("Contraseña no proporcionada")
                            
                            out = certificacion.decrypt_hybrid_file(hybrid_file=infile, identity=ident, password=pw, output_file=None)
                            print(f"Archivo descifrado por {ident} → {out}")
                        except Exception:
                            import traceback
                            traceback.print_exc()
                            raise
                    else:
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
                except Exception:
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
        """Muestra las claves guardadas del usuario activo (requiere contraseña)."""
        # Obtener usuario activo
        active_user = self.user_var.get()
        if active_user == "Seleccionar usuario...":
            messagebox.showerror("Error", "Debes seleccionar un usuario activo primero")
            return
        
        # Solicitar contraseña
        from tkinter import simpledialog
        password = simpledialog.askstring("Contraseña", 
            f"Contraseña de {active_user} para ver claves guardadas:", 
            show='*', 
            parent=self)
        
        if not password:
            return
        
        # Validar contraseña explícitamente antes de intentar leer las claves
        try:
            import certificacion
            # Intentar descifrar la clave privada para validar la contraseña
            certificacion._decrypt_user_private_key(active_user, password)
        except Exception:
            messagebox.showerror("Error de Autenticación", f"Contraseña incorrecta para {active_user}.")
            return

        # Obtener claves del usuario (ahora es seguro proceder)
        try:
            import user_keys
            stored_keys = user_keys.get_user_keys(active_user, password)
        except FileNotFoundError:
            messagebox.showinfo("Sin claves", f"No hay claves guardadas para {active_user}")
            return
        except ValueError as e:
            # Aunque ya validamos, mantenemos esto por seguridad extra
            messagebox.showerror("Error", f"Contraseña incorrecta o error al leer claves: {e}")
            return
        except Exception as e:
            messagebox.showerror("Error", f"Error al leer claves: {e}")
            return

        if not stored_keys:
            messagebox.showinfo("Sin claves", f"No hay claves guardadas para {active_user}")
            return

        # Heredar estilos de la ventana principal
        label_bg = None if self.panel_image is not None else "#222222"
        label_fg = "#79b670" if self.panel_image is None else "#000000"
        button_bg = "#3a8b8a" if self.panel_image is None else None
        button_fg = "#000000"

        # Crear diálogo de selección
        dialog = tk.Toplevel(self)
        dialog.title(f"🔑 Claves de {active_user}")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(bg=label_bg)
        dialog.geometry("700x400")

        # Lista de claves
        frame = tk.Frame(dialog, bg=label_bg, padx=10, pady=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Headers
        tk.Label(frame, text="Fecha", bg=label_bg, fg=label_fg, font=("Arial", 9, "bold")).grid(row=0, column=0, padx=5, pady=5)
        tk.Label(frame, text="Algoritmo", bg=label_bg, fg=label_fg, font=("Arial", 9, "bold")).grid(row=0, column=1, padx=5, pady=5)
        tk.Label(frame, text="Modo", bg=label_bg, fg=label_fg, font=("Arial", 9, "bold")).grid(row=0, column=2, padx=5, pady=5)
        tk.Label(frame, text="Archivo", bg=label_bg, fg=label_fg, font=("Arial", 9, "bold")).grid(row=0, column=3, padx=5, pady=5)
        tk.Label(frame, text="Clave", bg=label_bg, fg=label_fg, font=("Arial", 9, "bold")).grid(row=0, column=4, padx=5, pady=5)

        # Función para eliminar una clave
        def delete_key(index):
            try:
                import user_keys
                user_keys.delete_user_key(active_user, password, index)
                messagebox.showinfo("Éxito", "Clave eliminada correctamente")
                dialog.destroy()
                self.buscarClaveGuardada()  # Refrescar
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo eliminar la clave: {e}")

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
            self.output_txt.insert(tk.END, f"✓ Clave seleccionada\n")
            self.output_txt.insert(tk.END, f"  Usuario: {active_user}\n")
            self.output_txt.insert(tk.END, f"  Fecha: {entry['timestamp']}\n")
            self.output_txt.insert(tk.END, f"  Algoritmo: {entry['algorithm']}\n")
            self.output_txt.insert(tk.END, f"  Modo: {entry['mode']}\n")
            self.output_txt.insert(tk.END, f"  Clave: {entry['key']}\n")
            if entry.get("iv"):
                self.output_txt.insert(tk.END, f"  IV: {entry['iv']}\n")
            if entry.get("filename"):
                self.output_txt.insert(tk.END, f"  Archivo: {entry['filename']}\n")
            dialog.destroy()

        # Mostrar claves
        for i, entry in enumerate(stored_keys):
            tk.Label(frame, text=entry["timestamp"][:16], bg=label_bg, fg=label_fg).grid(row=i+1, column=0, padx=5, pady=2)
            tk.Label(frame, text=entry["algorithm"], bg=label_bg, fg=label_fg).grid(row=i+1, column=1, padx=5, pady=2)
            tk.Label(frame, text=entry["mode"], bg=label_bg, fg=label_fg).grid(row=i+1, column=2, padx=5, pady=2)
            
            # Mostrar nombre de archivo si existe
            filename = entry.get("filename", "Sin nombre")
            if len(filename) > 20:
                filename = filename[:17] + "..."
            tk.Label(frame, text=filename, bg=label_bg, fg=label_fg).grid(row=i+1, column=3, padx=5, pady=2)
            
            key_preview = entry["key"][:12] + "..."
            tk.Label(frame, text=key_preview, bg=label_bg, fg=label_fg).grid(row=i+1, column=4, padx=5, pady=2)
            tk.Button(frame, text="Seleccionar", command=lambda e=entry: select_key(e), bg=button_bg, fg=button_fg).grid(row=i+1, column=5, padx=5, pady=2)
            tk.Button(frame, text="Eliminar", command=lambda idx=i: delete_key(idx), bg="#c0392b", fg="white").grid(row=i+1, column=6, padx=5, pady=2)

        # Botón de cerrar
        close_btn = tk.Button(frame, text="Cerrar", command=dialog.destroy, bg=button_bg, fg=button_fg, width=15)
        close_btn.grid(row=len(stored_keys)+2, column=0, columnspan=7, pady=10)

        # Centrar diálogo
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = (dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (dialog.winfo_screenheight() // 2) - (height // 2)
        dialog.geometry(f"{width}x{height}+{x}+{y}")

    def manage_certificates(self) -> None:
        """Abrir diálogo para crear CA, crear usuarios y listar certificados."""
        try:
            dialog = tk.Toplevel(self)
            dialog.title("Gestionar certificados")
            dialog.transient(self)
            dialog.grab_set()
            dialog.geometry("550x550")  # Aumentado de 450 a 550 para ver todos los botones
            dialog.resizable(False, False)


            frame = tk.Frame(dialog, padx=15, pady=15)
            frame.pack(fill=tk.BOTH, expand=True)

            
            ca_frame = tk.Frame(frame, bg="#f0f0f0", padx=10, pady=10)
            ca_frame.pack(fill=tk.X, pady=(0, 15))


            # Sección: Crear Usuarios
            tk.Label(frame, text="👤 CREAR USUARIO", font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(15, 10))
            
            user_frame = tk.Frame(frame, bg="#f9f9f9", padx=10, pady=10)
            user_frame.pack(fill=tk.X, pady=(0, 15))

            tk.Label(user_frame, text="Identidad:", bg="#f9f9f9").pack(anchor=tk.W)
            id_var = tk.StringVar()
            id_entry = tk.Entry(user_frame, textvariable=id_var, width=40)
            id_entry.pack(fill=tk.X, pady=(0, 10))

            tk.Label(user_frame, text="Contraseña:", bg="#f9f9f9").pack(anchor=tk.W)
            pw_var = tk.StringVar()
            pw_entry = tk.Entry(user_frame, textvariable=pw_var, show='*', width=40)
            pw_entry.pack(fill=tk.X, pady=(0, 10))

            def _create_user():
                ident = id_var.get().strip()
                pw = pw_var.get()
                if not (ident and pw):
                    messagebox.showwarning("Faltan datos", "Introduce identidad y contraseña")
                    return
                # Use stored license implicitly; create_user will raise if CA/license missing
                try:
                    certificacion.create_user(ident, pw)
                    messagebox.showinfo("✓ Usuario creado", f"Usuario '{ident}' creado con éxito")
                    id_entry.delete(0, tk.END)
                    pw_entry.delete(0, tk.END)
                    # refresh lists
                    _refresh_list()
                    self.refresh_user_list()  # Actualizar combobox de la ventana principal
                except Exception as e:
                    messagebox.showerror("✕ Error usuario", f"Error creando usuario: {e}")

            tk.Button(user_frame, text="Crear usuario", command=_create_user, bg="#27ae60", fg="white").pack(anchor=tk.W)

            # Sección: Certificados disponibles
            tk.Label(frame, text="📋 CERTIFICADOS DISPONIBLES", font=("Arial", 11, "bold")).pack(anchor=tk.W, pady=(15, 10))
            
            listbox_frame = tk.Frame(frame)
            listbox_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

            scrollbar = tk.Scrollbar(listbox_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            listbox = tk.Listbox(listbox_frame, width=80, height=8, yscrollcommand=scrollbar.set)
            listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=listbox.yview)

            def _refresh_list():
                listbox.delete(0, tk.END)
                try:
                    certs = certificacion.list_certificates()
                    if not certs:
                        listbox.insert(tk.END, "No hay certificados disponibles")
                    else:
                        for c in certs:
                            state = "✓ VÁLIDO" if c.get('valid') else "✕ INVÁLIDO"
                            listbox.insert(tk.END, f"{c.get('identity'):20} [{state}]")
                except Exception as e:
                    messagebox.showerror("Error", f"No se pudieron listar certificados: {e}")

            def _delete_user():
                sel = listbox.curselection()
                if not sel:
                    messagebox.showwarning("Sin selección", "Selecciona un usuario para eliminar")
                    return
                idx = sel[0]
                try:
                    certs = certificacion.list_certificates()
                    if idx < len(certs):
                        user_identity = certs[idx].get('identity')
                        if messagebox.askyesno("Confirmar", f"¿Eliminar usuario '{user_identity}' y su certificado?"):
                            # Eliminar archivos del usuario
                            from pathlib import Path
                            fn = certificacion._safe_filename(user_identity)
                            cert_path = Path("certs/users") / f"{fn}.cert"
                            key_path = Path("certs/users") / f"{fn}.key.enc"
                            try:
                                cert_path.unlink()
                                key_path.unlink()
                                messagebox.showinfo("✓ Eliminado", f"Usuario '{user_identity}' eliminado")
                                _refresh_list()
                                self.refresh_user_list()  # Actualizar combobox
                            except Exception as e:
                                messagebox.showerror("Error", f"Error al eliminar: {e}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))

            # Frame de botones
            btn_frame = tk.Frame(frame)
            btn_frame.pack(fill=tk.X, pady=(10, 0))

            tk.Button(btn_frame, text="🔄 Refrescar", command=_refresh_list, bg="#95a5a6", fg="white").pack(side=tk.LEFT, padx=5)
            tk.Button(btn_frame, text="🗑 Eliminar usuario", command=_delete_user, bg="#e74c3c", fg="white").pack(side=tk.LEFT, padx=5)
            tk.Button(btn_frame, text="Cerrar", command=dialog.destroy, bg="#34495e", fg="white").pack(side=tk.RIGHT, padx=5)

            _refresh_list()
        except Exception as e:
            messagebox.showerror("Error", f"Error en gestión de certificados: {e}")


    def select_recipients(self) -> None:
        """Permite seleccionar uno o varios destinatarios para cifrado híbrido con interfaz mejorada."""
        try:
            certs = certificacion.list_certificates()
            valid_certs = [c for c in certs if c.get('valid')]
        except Exception as e:
            messagebox.showerror("Error", f"No se pudieron obtener certificados: {e}")
            return

        if not valid_certs:
            messagebox.showwarning("Sin certificados", "No hay certificados válidos disponibles.")
            return

        dialog = tk.Toplevel(self)
        dialog.title("🔐 Cifrado Múltiple - Seleccionar Destinatarios")
        dialog.transient(self)
        dialog.grab_set()
        dialog.geometry("550x500")
        dialog.configure(bg="#f5f5f5")

        # Frame principal
        main_frame = tk.Frame(dialog, padx=20, pady=20, bg="#f5f5f5")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Título
        title_label = tk.Label(
            main_frame, 
            text="Selecciona los usuarios que podrán descifrar el archivo:", 
            font=("Arial", 11, "bold"),
            bg="#f5f5f5",
            fg="#2c3e50"
        )
        title_label.pack(anchor=tk.W, pady=(0, 15))

        # Frame con scroll para los usuarios
        canvas_frame = tk.Frame(main_frame, bg="#f5f5f5")
        canvas_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        # Canvas y scrollbar
        canvas = tk.Canvas(canvas_frame, bg="#f5f5f5", highlightthickness=0)
        scrollbar = tk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg="#f5f5f5")

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Diccionario para rastrear selecciones
        selected_users = {}

        def toggle_user(identity, button):
            """Toggle user selection and update button appearance"""
            if identity in selected_users and selected_users[identity]:
                # Deseleccionar
                selected_users[identity] = False
                button.configure(
                    bg="#ecf0f1",
                    fg="#2c3e50",
                    relief=tk.RAISED,
                    text=f"□ {identity}"
                )
            else:
                # Seleccionar
                selected_users[identity] = True
                button.configure(
                    bg="#27ae60",
                    fg="white",
                    relief=tk.SUNKEN,
                    text=f"✓ {identity}"
                )

        # Crear botón para cada usuario
        for idx, cert in enumerate(valid_certs):
            identity = cert.get('identity')
            selected_users[identity] = False

            # Frame para cada usuario
            user_frame = tk.Frame(scrollable_frame, bg="#f5f5f5")
            user_frame.pack(fill=tk.X, pady=5, padx=5)

            # Botón de usuario
            user_btn = tk.Button(
                user_frame,
                text=f"□ {identity}",
                font=("Arial", 10),
                bg="#ecf0f1",
                fg="#2c3e50",
                activebackground="#bdc3c7",
                activeforeground="#2c3e50",
                relief=tk.RAISED,
                bd=2,
                padx=20,
                pady=12,
                cursor="hand2",
                anchor="w",
                width=40,
                command=lambda i=identity, b=None: toggle_user(i, user_btn)
            )
            # Guardar referencia al botón para poder actualizarlo
            user_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)

            # Actualizar el comando con la referencia correcta al botón
            user_btn.configure(command=lambda i=identity, b=user_btn: toggle_user(i, b))

        # Contador de seleccionados
        count_label = tk.Label(
            main_frame,
            text="Seleccionados: 0",
            font=("Arial", 9),
            bg="#f5f5f5",
            fg="#7f8c8d"
        )
        count_label.pack(anchor=tk.W, pady=(0, 10))

        def update_count():
            """Actualizar contador de usuarios seleccionados"""
            count = sum(1 for v in selected_users.values() if v)
            count_label.configure(text=f"Seleccionados: {count}")
            dialog.after(100, update_count)

        update_count()

        # Frame de botones de acción
        btn_frame = tk.Frame(main_frame, bg="#f5f5f5")
        btn_frame.pack(fill=tk.X, pady=(10, 0))

        def _select_all():
            """Seleccionar todos los usuarios"""
            for child in scrollable_frame.winfo_children():
                for widget in child.winfo_children():
                    if isinstance(widget, tk.Button):
                        identity = widget.cget("text").replace("□ ", "").replace("✓ ", "")
                        if identity in selected_users and not selected_users[identity]:
                            toggle_user(identity, widget)

        def _deselect_all():
            """Deseleccionar todos los usuarios"""
            for child in scrollable_frame.winfo_children():
                for widget in child.winfo_children():
                    if isinstance(widget, tk.Button):
                        identity = widget.cget("text").replace("□ ", "").replace("✓ ", "")
                        if identity in selected_users and selected_users[identity]:
                            toggle_user(identity, widget)

        def _ok():
            """Confirmar selección"""
            sels = [identity for identity, selected in selected_users.items() if selected]
            if not sels:
                messagebox.showwarning("Sin selección", "Debes seleccionar al menos un destinatario.")
                return
            
            # Auto-inclusión obligatoria del usuario activo
            active_user = self.user_var.get()
            if active_user != "Seleccionar usuario...":
                if active_user not in sels:
                    sels.append(active_user)
                    messagebox.showinfo("Auto-inclusión", 
                        f"✓ Te has añadido automáticamente ({active_user}) a los destinatarios.\n"
                        f"Esto te permite descifrar el archivo más tarde.")
            
            self.recipients = sels
            self.output_txt.delete('1.0', tk.END)
            self.output_txt.insert(tk.END, f"✓ Cifrado múltiple configurado\n")
            self.output_txt.insert(tk.END, f"  Destinatarios: {', '.join(sels)}\n")
            self.output_txt.insert(tk.END, f"  Próximo archivo será cifrado para {len(sels)} usuario(s).\n")
            dialog.destroy()

        def _cancel():
            """Cancelar selección"""
            dialog.destroy()

        # Botones de acción
        tk.Button(
            btn_frame, 
            text="Seleccionar Todos", 
            command=_select_all, 
            width=15, 
            bg="#3498db", 
            fg="white",
            font=("Arial", 9)
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            btn_frame, 
            text="Deseleccionar Todos", 
            command=_deselect_all, 
            width=15, 
            bg="#95a5a6", 
            fg="white",
            font=("Arial", 9)
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            btn_frame, 
            text="✓ Confirmar", 
            command=_ok, 
            width=12, 
            bg="#27ae60", 
            fg="white",
            font=("Arial", 9, "bold")
        ).pack(side=tk.RIGHT, padx=5)

        tk.Button(
            btn_frame, 
            text="✕ Cancelar", 
            command=_cancel, 
            width=12, 
            bg="#e74c3c", 
            fg="white",
            font=("Arial", 9)
        ).pack(side=tk.RIGHT, padx=5)


